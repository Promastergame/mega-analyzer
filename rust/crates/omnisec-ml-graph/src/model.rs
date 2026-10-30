//! Cross-modal GNN model for vulnerability detection

use omnisec_json::{FromJson, ToJson};

/// Configuration for the GNN model
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct GNNConfig {
    /// Number of hidden layers
    pub num_hidden_layers: usize,
    /// Hidden layer size
    pub hidden_size: usize,
    /// Number of output classes (vulnerability types)
    pub num_classes: usize,
    /// Dropout rate
    pub dropout_rate: f32,
    /// Learning rate
    pub learning_rate: f32,
    /// Batch size
    pub batch_size: usize,
}

impl Default for GNNConfig {
    fn default() -> Self {
        GNNConfig {
            num_hidden_layers: 3,
            hidden_size: 128,
            num_classes: 10,
            dropout_rate: 0.2,
            learning_rate: 0.001,
            batch_size: 32,
        }
    }
}

/// Prediction from the model
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct Prediction {
    /// Per-class probabilities
    pub class_probs: Vec<f32>,
    /// Predicted class
    pub predicted_class: usize,
    /// Confidence score
    pub confidence: f32,
    /// Explanation/attribution
    pub attribution: Vec<f32>,
}

/// Cross-modal GNN model
pub struct CrossModalGNN {
    config: GNNConfig,
    weights: Vec<Vec<f32>>,
    biases: Vec<Vec<f32>>,
}

/// Deterministic 64-bit mixer (`splitmix64`) for reproducible init.
fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = x;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// One Xavier-uniform sample in `[-limit, limit]` from a deterministic
/// stream keyed by `(layer, index)`.
fn xavier_sample(layer: u64, index: u64, limit: f32) -> f32 {
    let key = layer
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(index.wrapping_mul(0xD1B5_4A32_80AE_1659));
    let u = (splitmix64(key) >> 11) as f32 / (1u64 << 53) as f32; // [0, 1)
    u.mul_add(2.0, -1.0) * limit
}

impl CrossModalGNN {
    /// Create a new model with the given configuration.
    ///
    /// Weights use Xavier-uniform initialization driven by a deterministic
    /// `splitmix64` stream (seeded per layer) so model construction is
    /// reproducible without an RNG dependency.
    pub fn new(config: GNNConfig) -> Self {
        let mut weights = Vec::new();
        let mut biases = Vec::new();

        // Initialize weights and biases for each layer
        let input_size = 28; // Typical feature vector size
        let mut prev_size = input_size;

        for layer in 0..config.num_hidden_layers {
            let limit = (6.0 / (prev_size + config.hidden_size) as f32).sqrt();
            let weight_matrix = (0..prev_size * config.hidden_size)
                .map(|i| xavier_sample(layer as u64, i as u64, limit))
                .collect();
            weights.push(weight_matrix);

            // Initialize bias vector
            let bias_vector = vec![0.0; config.hidden_size];
            biases.push(bias_vector);

            prev_size = config.hidden_size;
        }

        // Output layer
        let limit = (6.0 / (prev_size + config.num_classes) as f32).sqrt();
        let output_weights = (0..prev_size * config.num_classes)
            .map(|i| xavier_sample(config.num_hidden_layers as u64, i as u64, limit))
            .collect();
        weights.push(output_weights);

        let output_bias = vec![0.0; config.num_classes];
        biases.push(output_bias);

        CrossModalGNN {
            config,
            weights,
            biases,
        }
    }

    /// Run inference on input features
    pub fn predict(&self, features: &[f32]) -> crate::Result<Prediction> {
        if features.is_empty() {
            return Err(crate::Error::ModelError("Empty feature vector".to_string()));
        }

        // Forward pass through the network
        let mut activations = features.to_vec();

        for layer_idx in 0..self.weights.len() - 1 {
            activations = self.forward_layer(&activations, layer_idx, true);
        }

        // Output layer (no activation)
        let output = self.forward_layer(&activations, self.weights.len() - 1, false);

        // Softmax to get probabilities
        let class_probs = self.softmax(&output);

        // Find predicted class
        let predicted_class = class_probs
            .iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(idx, _)| idx)
            .unwrap_or(0);

        let confidence = class_probs[predicted_class];

        // Compute attribution (simplified)
        let attribution = self.compute_attribution(features);

        Ok(Prediction {
            class_probs,
            predicted_class,
            confidence,
            attribution,
        })
    }

    /// Forward pass through a single layer
    fn forward_layer(&self, input: &[f32], layer_idx: usize, apply_activation: bool) -> Vec<f32> {
        let weights = &self.weights[layer_idx];
        let biases = &self.biases[layer_idx];

        let output_size = biases.len();
        let input_size = input.len();

        let mut output = vec![0.0; output_size];

        // Matrix multiplication: output = input @ weights + bias
        for i in 0..output_size {
            let mut sum = biases[i];
            for j in 0..input_size {
                sum += input[j] * weights[i * input_size + j];
            }
            output[i] = sum;
        }

        // Apply activation function
        if apply_activation {
            output = self.relu(&output);
        }

        output
    }

    /// ReLU activation function
    fn relu(&self, x: &[f32]) -> Vec<f32> {
        x.iter().map(|&v| v.max(0.0)).collect()
    }

    /// Softmax function
    fn softmax(&self, x: &[f32]) -> Vec<f32> {
        let max = x.iter().fold(f32::NEG_INFINITY, |a, &b| a.max(b));
        let exp_x: Vec<f32> = x.iter().map(|&v| (v - max).exp()).collect();
        let sum: f32 = exp_x.iter().sum();

        exp_x.iter().map(|&v| v / sum).collect()
    }

    /// Compute feature attribution via input × first-layer sensitivity:
    /// for each input feature, the L1 mass of its outgoing weights scaled
    /// by the feature magnitude, normalized to sum to 1. This highlights
    /// which inputs drive the hidden representation most.
    fn compute_attribution(&self, features: &[f32]) -> Vec<f32> {
        if self.weights.is_empty() {
            return features.to_vec();
        }
        let first = &self.weights[0];
        let out_dim = self.biases.first().map_or(0, Vec::len);
        let in_dim = features.len();
        if out_dim == 0 || first.len() < out_dim * in_dim {
            return features.to_vec();
        }
        let mut scores: Vec<f32> = features
            .iter()
            .enumerate()
            .map(|(j, f)| {
                let mass: f32 = (0..out_dim).map(|i| first[i * in_dim + j].abs()).sum();
                f.abs() * mass
            })
            .collect();
        let total: f32 = scores.iter().sum();
        if total > 0.0 {
            for s in &mut scores {
                *s /= total;
            }
        }
        scores
    }

    /// Get model configuration
    pub fn config(&self) -> &GNNConfig {
        &self.config
    }

    /// Save model to file
    pub fn save(&self, path: &str) -> crate::Result<()> {
        let serialized =
            omnisec_json::to_json_string(&(self.config.clone(), &self.weights, &self.biases));

        std::fs::write(path, serialized)
            .map_err(|e| crate::Error::ModelError(format!("Failed to write model: {}", e)))?;

        Ok(())
    }

    /// Load model from file
    pub fn load(path: &str) -> crate::Result<Self> {
        let data = std::fs::read_to_string(path)
            .map_err(|e| crate::Error::ModelError(format!("Failed to read model: {}", e)))?;

        let (config, weights, biases): (GNNConfig, Vec<Vec<f32>>, Vec<Vec<f32>>) =
            omnisec_json::from_json_str(&data)
                .map_err(|e| crate::Error::ModelError(format!("Deserialization failed: {}", e)))?;

        Ok(CrossModalGNN {
            config,
            weights,
            biases,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_model_creation() {
        let config = GNNConfig::default();
        let model = CrossModalGNN::new(config);
        assert_eq!(model.config().num_classes, 10);
    }

    #[test]
    fn test_prediction() {
        let config = GNNConfig::default();
        let model = CrossModalGNN::new(config);

        let features = vec![0.5; 28];
        let prediction = model.predict(&features);

        assert!(prediction.is_ok());
        let pred = prediction.unwrap();
        assert_eq!(pred.class_probs.len(), 10);
        assert!(pred.confidence >= 0.0 && pred.confidence <= 1.0);
    }

    #[test]
    fn test_softmax() {
        let model = CrossModalGNN::new(GNNConfig::default());
        let input = vec![1.0, 2.0, 3.0];
        let output = model.softmax(&input);

        // Check that output sums to 1.0
        let sum: f32 = output.iter().sum();
        assert!((sum - 1.0).abs() < 0.001);
    }
}
