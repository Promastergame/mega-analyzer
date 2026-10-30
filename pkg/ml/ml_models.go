package ml

import (
	"fmt"
	"math"
	"math/rand"
	"sort"
)

// ═══════════════════════════════════════════════════════════════════════════
// LOGISTIC REGRESSION — настоящий ML для классификации методов
// ═══════════════════════════════════════════════════════════════════════════

// LogisticRegression implements binary classification using gradient descent
type LogisticRegression struct {
	weights      []float64
	bias         float64
	learningRate float64
	epochs       int
	lambda       float64 // regularization
	featureNames []string
	trained      bool

	// Optional z-score normalization; disabled by default for compatibility.
	standardize  bool
	featureMean  []float64
	featureScale []float64

	// Early stopping configuration. When tolerance > 0 and patience > 0,
	// training halts after `patience` consecutive epochs whose log-loss
	// improvement stays below `tolerance`. This avoids burning epochs after
	// convergence (the original 1000-epoch fixed loop) and surfaces the
	// "silent non-convergence" case via TrainingHistory.
	tolerance float64
	patience  int

	// TrainingHistory captures per-epoch log-loss for diagnostics. Populated
	// only when tolerance > 0 (i.e., when early stopping is active), so the
	// hot path of pure-fixed-epoch training stays allocation-free.
	TrainingHistory []float64

	// LastConverged reports whether the most recent Fit() stopped because
	// of early stopping (true) or hit the epoch ceiling (false).
	LastConverged bool

	// LastEpochs records how many epochs the most recent Fit() actually ran.
	// Always equal to len(TrainingHistory) when history is recorded.
	LastEpochs int
}

// NewLogisticRegression creates a new logistic regression model
func NewLogisticRegression(learningRate float64, epochs int, lambda float64) *LogisticRegression {
	return &LogisticRegression{
		learningRate: learningRate,
		epochs:       epochs,
		lambda:       lambda,
		// Sensible defaults for early stopping. Callers that want the legacy
		// behaviour (run all `epochs`) can call WithEarlyStopping(0, 0).
		tolerance: 1e-5,
		patience:  10,
	}
}

// DefaultLogisticRegression returns a model with sensible defaults
func DefaultLogisticRegression() *LogisticRegression {
	return &LogisticRegression{
		learningRate: 0.1,
		epochs:       1000,
		lambda:       0.01, // L2 regularization
		tolerance:    1e-5,
		patience:     10,
	}
}

// WithEarlyStopping configures the convergence check used during Fit.
//
// `tolerance` is the minimum *relative* loss improvement that counts as
// progress; `patience` is the number of consecutive non-improving epochs
// tolerated before training halts. Setting either to 0 disables early
// stopping and reproduces the legacy fixed-epoch loop.
func (lr *LogisticRegression) WithEarlyStopping(tolerance float64, patience int) *LogisticRegression {
	lr.tolerance = tolerance
	lr.patience = patience
	return lr
}

// WithStandardization enables z-score normalization for training and inference.
func (lr *LogisticRegression) WithStandardization(enabled bool) *LogisticRegression {
	lr.standardize = enabled
	return lr
}

func (lr *LogisticRegression) prepareTrainingMatrix(X [][]float64) [][]float64 {
	if !lr.standardize || len(X) == 0 || len(X[0]) == 0 {
		lr.featureMean, lr.featureScale = nil, nil
		return X
	}
	n := len(X[0])
	lr.featureMean = make([]float64, n)
	lr.featureScale = make([]float64, n)
	for _, row := range X {
		if len(row) != n {
			lr.featureMean, lr.featureScale = nil, nil
			return X
		}
		for j, value := range row {
			lr.featureMean[j] += value
		}
	}
	for j := range lr.featureMean {
		lr.featureMean[j] /= float64(len(X))
	}
	for _, row := range X {
		for j, value := range row {
			d := value - lr.featureMean[j]
			lr.featureScale[j] += d * d
		}
	}
	for j := range lr.featureScale {
		lr.featureScale[j] = math.Sqrt(lr.featureScale[j] / float64(len(X)))
		if lr.featureScale[j] < 1e-12 {
			lr.featureScale[j] = 1
		}
	}
	return lr.transformMatrix(X)
}

func (lr *LogisticRegression) transformMatrix(X [][]float64) [][]float64 {
	if !lr.standardize || len(lr.featureMean) == 0 {
		return X
	}
	out := make([][]float64, len(X))
	for i, row := range X {
		out[i] = lr.transformRow(row)
	}
	return out
}

func (lr *LogisticRegression) transformRow(row []float64) []float64 {
	if !lr.standardize || len(lr.featureMean) != len(row) || len(lr.featureScale) != len(row) {
		return row
	}
	out := make([]float64, len(row))
	for i, value := range row {
		out[i] = (value - lr.featureMean[i]) / lr.featureScale[i]
	}
	return out
}

// sigmoid function
func sigmoid(z float64) float64 {
	return 1.0 / (1.0 + math.Exp(-z))
}

// Fit trains the model on training data.
//
// Fit is now a thin wrapper over FitWeighted with unit weights: with every
// weight equal to 1, FitWeighted reduces exactly to plain (unweighted)
// gradient descent (sumW == m, so every gradient/loss normalisation matches
// the legacy loop). This removes the previously duplicated training loop and
// keeps a single, tested optimisation path.
func (lr *LogisticRegression) Fit(X [][]float64, y []int, featureNames []string) error {
	if len(X) != len(y) {
		return fmt.Errorf("X and y must have same length")
	}
	if len(X) == 0 {
		return fmt.Errorf("training data cannot be empty")
	}
	weights := make([]float64, len(X))
	for i := range weights {
		weights[i] = 1.0
	}
	return lr.FitWeighted(X, y, weights, featureNames)
}

// FitWeighted is Fit with per-sample weights, useful for class-imbalance
// handling. Each example's gradient contribution is multiplied by its
// weight, so a positive class with `weight=10` exerts the same pull on the
// optimiser as ten positive examples.
//
// Pass nil weights to fall through to the unweighted Fit. Negative weights
// are rejected.
func (lr *LogisticRegression) FitWeighted(X [][]float64, y []int, weights []float64, featureNames []string) error {
	if weights == nil {
		return lr.Fit(X, y, featureNames)
	}
	if len(X) != len(y) || len(X) != len(weights) {
		return fmt.Errorf("X (%d), y (%d), weights (%d) must align", len(X), len(y), len(weights))
	}
	if len(X) == 0 {
		return fmt.Errorf("training data cannot be empty")
	}
	for i, w := range weights {
		if w < 0 {
			return fmt.Errorf("weight[%d] must be non-negative, got %f", i, w)
		}
	}

	X = lr.prepareTrainingMatrix(X)
	nFeatures := len(X[0])
	lr.weights = make([]float64, nFeatures)
	lr.bias = 0
	lr.featureNames = featureNames
	lr.trained = false
	lr.LastConverged = false
	lr.LastEpochs = 0

	earlyStop := lr.tolerance > 0 && lr.patience > 0
	if earlyStop {
		lr.TrainingHistory = lr.TrainingHistory[:0]
	} else {
		lr.TrainingHistory = nil
	}

	// Effective sample count used to normalise gradients. We use the sum of
	// weights so a tiny minority class doesn't get washed out: doubling the
	// minority's weights doubles its gradient pull, not its denominator.
	var sumW float64
	for _, w := range weights {
		sumW += w
	}
	if sumW == 0 {
		return fmt.Errorf("all weights are zero")
	}

	prevLoss := math.Inf(1)
	stagnant := 0

	for epoch := 0; epoch < lr.epochs; epoch++ {
		dw := make([]float64, nFeatures)
		db := 0.0
		loss := 0.0

		for i := 0; i < len(X); i++ {
			z := lr.bias
			for j := 0; j < nFeatures; j++ {
				z += lr.weights[j] * X[i][j]
			}
			pred := sigmoid(z)
			w := weights[i]

			if earlyStop {
				const eps = 1e-12
				p := math.Max(eps, math.Min(1.0-eps, pred))
				if y[i] == 1 {
					loss -= w * math.Log(p)
				} else {
					loss -= w * math.Log(1.0-p)
				}
			}

			err := w * (pred - float64(y[i]))
			for j := 0; j < nFeatures; j++ {
				dw[j] += err * X[i][j]
			}
			db += err
		}

		for j := 0; j < nFeatures; j++ {
			lr.weights[j] -= lr.learningRate * (dw[j]/sumW + lr.lambda*lr.weights[j])
		}
		lr.bias -= lr.learningRate * db / sumW

		if earlyStop {
			loss /= sumW
			lr.TrainingHistory = append(lr.TrainingHistory, loss)
			lr.LastEpochs = epoch + 1
			if math.IsInf(prevLoss, 1) {
				prevLoss = loss
				continue
			}
			improvement := (prevLoss - loss) / math.Max(1e-12, math.Abs(prevLoss))
			if improvement > lr.tolerance {
				stagnant = 0
				prevLoss = loss
			} else {
				stagnant++
				if stagnant >= lr.patience {
					lr.LastConverged = true
					break
				}
			}
		} else {
			lr.LastEpochs = epoch + 1
		}
	}

	lr.trained = true
	return nil
}

// BalancedClassWeights computes inverse-frequency weights for binary
// classification. With class counts (n0, n1), positive examples receive
// weight n_total/(2*n1) and negatives n_total/(2*n0) — matching
// scikit-learn's `class_weight="balanced"` heuristic.
//
// Returns one weight per training example, ready for FitWeighted.
func BalancedClassWeights(y []int) []float64 {
	if len(y) == 0 {
		return nil
	}
	var n0, n1 int
	for _, lbl := range y {
		if lbl == 1 {
			n1++
		} else {
			n0++
		}
	}
	w := make([]float64, len(y))
	total := float64(len(y))
	w0, w1 := 1.0, 1.0
	if n0 > 0 {
		w0 = total / (2.0 * float64(n0))
	}
	if n1 > 0 {
		w1 = total / (2.0 * float64(n1))
	}
	for i, lbl := range y {
		if lbl == 1 {
			w[i] = w1
		} else {
			w[i] = w0
		}
	}
	return w
}

// PartialFit performs a single SGD step on one (or a few) labeled examples.
func (lr *LogisticRegression) PartialFit(X [][]float64, y []int, passes int) error {
	if !lr.trained {
		return fmt.Errorf("PartialFit requires a Fit() call first to set the weight shape")
	}
	if len(X) != len(y) {
		return fmt.Errorf("X and y must have same length")
	}
	if len(X) == 0 {
		return nil
	}
	if len(X[0]) != len(lr.weights) {
		return fmt.Errorf("expected %d features, got %d", len(lr.weights), len(X[0]))
	}
	if passes <= 0 {
		passes = 1
	}

	for p := 0; p < passes; p++ {
		for i, rawRow := range X {
			row := lr.transformRow(rawRow)
			z := lr.bias
			for j, f := range row {
				z += lr.weights[j] * f
			}
			pred := sigmoid(z)
			err := pred - float64(y[i])
			for j, f := range row {
				lr.weights[j] -= lr.learningRate * (err*f + lr.lambda*lr.weights[j])
			}
			lr.bias -= lr.learningRate * err
		}
	}
	return nil
}

// Predict returns probability of positive class (0..1)
func (lr *LogisticRegression) Predict(features []float64) (float64, error) {
	if !lr.trained {
		return 0, fmt.Errorf("model not trained yet")
	}
	if len(features) != len(lr.weights) {
		return 0, fmt.Errorf("expected %d features, got %d", len(lr.weights), len(features))
	}

	features = lr.transformRow(features)
	z := lr.bias
	for i, f := range features {
		z += lr.weights[i] * f
	}

	return sigmoid(z), nil
}

// PredictClass returns class (0 or 1) with threshold
func (lr *LogisticRegression) PredictClass(features []float64, threshold float64) (int, error) {
	prob, err := lr.Predict(features)
	if err != nil {
		return 0, err
	}
	if prob >= threshold {
		return 1, nil
	}
	return 0, nil
}

// FeatureImportance returns sorted feature names by absolute weight
type FeatureImportance struct {
	Name      string
	Weight    float64
	AbsWeight float64
}

// GetFeatureImportance returns features sorted by importance (descending)
func (lr *LogisticRegression) GetFeatureImportance() []FeatureImportance {
	if !lr.trained {
		return nil
	}

	importance := make([]FeatureImportance, len(lr.weights))
	for i, w := range lr.weights {
		name := "unknown"
		if i < len(lr.featureNames) {
			name = lr.featureNames[i]
		}
		importance[i] = FeatureImportance{
			Name:      name,
			Weight:    w,
			AbsWeight: math.Abs(w),
		}
	}

	sort.Slice(importance, func(i, j int) bool {
		return importance[i].AbsWeight > importance[j].AbsWeight
	})

	return importance
}

// SaveWeights returns model parameters for serialization
func (lr *LogisticRegression) SaveWeights() map[string]interface{} {
	return map[string]interface{}{
		"weights":       lr.weights,
		"bias":          lr.bias,
		"features":      lr.featureNames,
		"trained":       lr.trained,
		"standardize":   lr.standardize,
		"feature_mean":  lr.featureMean,
		"feature_scale": lr.featureScale,
	}
}

// LoadWeights loads model parameters from serialization
func (lr *LogisticRegression) LoadWeights(data map[string]interface{}) error {
	weights, err := floatSliceFromAny(data["weights"])
	if err != nil {
		return fmt.Errorf("invalid weights format: %w", err)
	}
	bias, ok := floatFromAny(data["bias"])
	if !ok {
		return fmt.Errorf("invalid bias format")
	}
	features, err := stringSliceFromAny(data["features"])
	if err != nil {
		return fmt.Errorf("invalid features format: %w", err)
	}
	lr.weights = weights
	lr.bias = bias
	lr.featureNames = features
	lr.trained = true
	if v, ok := data["standardize"].(bool); ok {
		lr.standardize = v
	}
	if mean, e := floatSliceFromAny(data["feature_mean"]); e == nil {
		lr.featureMean = mean
	}
	if scale, e := floatSliceFromAny(data["feature_scale"]); e == nil {
		lr.featureScale = scale
	}
	return nil
}

func floatFromAny(v interface{}) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	default:
		return 0, false
	}
}

func floatSliceFromAny(v interface{}) ([]float64, error) {
	switch values := v.(type) {
	case nil:
		return nil, nil
	case []float64:
		return append([]float64(nil), values...), nil
	case []interface{}:
		out := make([]float64, len(values))
		for i, item := range values {
			value, ok := floatFromAny(item)
			if !ok {
				return nil, fmt.Errorf("element %d is not numeric", i)
			}
			out[i] = value
		}
		return out, nil
	default:
		return nil, fmt.Errorf("expected numeric slice")
	}
}

func stringSliceFromAny(v interface{}) ([]string, error) {
	switch values := v.(type) {
	case nil:
		return nil, nil
	case []string:
		return append([]string(nil), values...), nil
	case []interface{}:
		out := make([]string, len(values))
		for i, item := range values {
			value, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("element %d is not a string", i)
			}
			out[i] = value
		}
		return out, nil
	default:
		return nil, fmt.Errorf("expected string slice")
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// TF-IDF + COSINE SIMILARITY — для сравнения APK с образцами
// ═══════════════════════════════════════════════════════════════════════════

// TFIDF implements Term Frequency-Inverse Document Frequency
type TFIDF struct {
	idf        map[string]float64
	vocabulary map[string]int
	docCount   int
}

// NewTFIDF creates a new TF-IDF vectorizer
func NewTFIDF() *TFIDF {
	return &TFIDF{
		idf:        make(map[string]float64),
		vocabulary: make(map[string]int),
	}
}

// Fit builds vocabulary and computes IDF from documents
func (tfidf *TFIDF) Fit(documents [][]string) {
	tfidf.docCount = len(documents)
	tfidf.idf = make(map[string]float64)

	// Build vocabulary and count document frequency
	for _, doc := range documents {
		seen := make(map[string]bool)
		for _, term := range doc {
			if !seen[term] {
				tfidf.idf[term]++
				seen[term] = true
			}
		}
	}

	// Build vocabulary indices
	tfidf.vocabulary = make(map[string]int)
	idx := 0
	for term := range tfidf.idf {
		tfidf.vocabulary[term] = idx
		idx++
	}

	// Compute IDF with smoothing
	for term, df := range tfidf.idf {
		tfidf.idf[term] = math.Log(float64(tfidf.docCount+1)/(df+1)) + 1
	}
}

// Transform converts documents to TF-IDF vectors
func (tfidf *TFIDF) Transform(documents [][]string) [][]float64 {
	vocabSize := len(tfidf.vocabulary)
	vectors := make([][]float64, len(documents))

	for i, doc := range documents {
		// Compute term frequency
		tf := make(map[string]int)
		for _, term := range doc {
			tf[term]++
		}

		// Build vector
		vector := make([]float64, vocabSize)
		for term, idf := range tfidf.idf {
			if idx, ok := tfidf.vocabulary[term]; ok {
				tfVal := float64(tf[term]) / float64(len(doc))
				vector[idx] = tfVal * idf
			}
		}

		// L2 normalize
		norm := 0.0
		for _, v := range vector {
			norm += v * v
		}
		norm = math.Sqrt(norm)
		if norm > 0 {
			for j := range vector {
				vector[j] /= norm
			}
		}

		vectors[i] = vector
	}

	return vectors
}

// FitTransform fits and transforms in one step
func (tfidf *TFIDF) FitTransform(documents [][]string) [][]float64 {
	tfidf.Fit(documents)
	return tfidf.Transform(documents)
}

// CosineSimilarity computes cosine similarity between two vectors
func CosineSimilarity(a, b []float64) float64 {
	if len(a) != len(b) {
		return 0
	}

	dot := 0.0
	normA := 0.0
	normB := 0.0

	for i := range a {
		dot += a[i] * b[i]
		normA += a[i] * a[i]
		normB += b[i] * b[i]
	}

	normA = math.Sqrt(normA)
	normB = math.Sqrt(normB)

	if normA == 0 || normB == 0 {
		return 0
	}

	return dot / (normA * normB)
}

// ═══════════════════════════════════════════════════════════════════════════
// RANDOM FOREST — простой ансамбль деревьев решений
// ═══════════════════════════════════════════════════════════════════════════

// DecisionTree represents a simple decision tree
type DecisionTree struct {
	featureIdx int
	threshold  float64
	left       *DecisionTree
	right      *DecisionTree
	prediction int // leaf prediction (0 or 1)
	isLeaf     bool
}

// RandomForest represents a random forest classifier
type RandomForest struct {
	trees        []*DecisionTree
	nTrees       int
	maxDepth     int
	maxFeatures  int // mtry: number of features sampled per split (0 = √nFeatures)
	seed         int64
	featureNames []string
	trained      bool
}

// NewRandomForest creates a new random forest
func NewRandomForest(nTrees int, maxDepth int) *RandomForest {
	return &RandomForest{
		nTrees:   nTrees,
		maxDepth: maxDepth,
		// 0 sentinel → resolved to floor(sqrt(nFeatures)) at Fit time.
		maxFeatures: 0,
		// Default seed of 0 means "non-reproducible" — Fit will pick a random
		// one. Tests that need determinism call WithSeed.
		seed: 0,
	}
}

// WithMaxFeatures sets `mtry` — how many features each split considers.
// Pass 0 to restore the √n default. Higher values approach a deterministic
// forest (no diversity); lower values increase ensemble variance reduction.
func (rf *RandomForest) WithMaxFeatures(m int) *RandomForest {
	if m < 0 {
		m = 0
	}
	rf.maxFeatures = m
	return rf
}

// WithSeed pins the PRNG seed used for bootstrap sampling and feature
// subsampling. Call this for reproducible test runs.
func (rf *RandomForest) WithSeed(seed int64) *RandomForest {
	rf.seed = seed
	return rf
}

// Fit trains the random forest
func (rf *RandomForest) Fit(X [][]float64, y []int, featureNames []string) error {
	if len(X) != len(y) {
		return fmt.Errorf("X and y must have same length")
	}
	if len(X) == 0 {
		return fmt.Errorf("training data cannot be empty")
	}

	rf.trees = make([]*DecisionTree, rf.nTrees)
	rf.featureNames = featureNames
	rf.trained = false

	// Resolve mtry. Default to floor(sqrt(nFeatures)), the canonical
	// Breiman default for classification RFs. Clamp to [1, nFeatures].
	nFeatures := len(X[0])
	mtry := rf.maxFeatures
	if mtry == 0 {
		mtry = int(math.Floor(math.Sqrt(float64(nFeatures))))
	}
	if mtry < 1 {
		mtry = 1
	}
	if mtry > nFeatures {
		mtry = nFeatures
	}

	// Master PRNG: deterministic when WithSeed was called, otherwise we
	// derive it from rand.Int63 so two parallel forests don't collide.
	var masterSeed int64
	if rf.seed != 0 {
		masterSeed = rf.seed
	} else {
		masterSeed = rand.Int63()
	}
	masterRng := rand.New(rand.NewSource(masterSeed))

	for i := 0; i < rf.nTrees; i++ {
		// Each tree gets its own independent PRNG so adding/removing a tree
		// doesn't perturb the others. Critical for OOB and incremental work.
		treeRng := rand.New(rand.NewSource(masterRng.Int63()))

		bootX, bootY := bootstrapSample(X, y, treeRng)
		rf.trees[i] = rf.buildTree(bootX, bootY, 0, mtry, treeRng)
	}

	rf.trained = true
	return nil
}

// Predict returns majority vote prediction
func (rf *RandomForest) Predict(features []float64) (int, error) {
	if !rf.trained {
		return 0, fmt.Errorf("model not trained yet")
	}

	votes := make([]int, 2) // 0 or 1

	for _, tree := range rf.trees {
		pred := rf.predictTree(tree, features)
		votes[pred]++
	}

	// Ties resolve to class 1 (positive). The original `>` strictly favoured
	// class 0 on ties, which combined with the broken bootstrap meant every
	// even-tree forest silently inherited the seed tree's bias.
	if votes[1] >= votes[0] {
		return 1, nil
	}
	return 0, nil
}

// PredictProbability returns fraction of trees voting for class 1
func (rf *RandomForest) PredictProbability(features []float64) (float64, error) {
	if !rf.trained {
		return 0, fmt.Errorf("model not trained yet")
	}

	votes := 0
	for _, tree := range rf.trees {
		votes += rf.predictTree(tree, features)
	}

	return float64(votes) / float64(len(rf.trees)), nil
}

func (rf *RandomForest) buildTree(X [][]float64, y []int, depth int, mtry int, rng *rand.Rand) *DecisionTree {
	// Base cases: pure node or max depth
	if len(y) == 0 {
		return &DecisionTree{isLeaf: true, prediction: 0}
	}

	// Check if all same class
	allSame := true
	for i := 1; i < len(y); i++ {
		if y[i] != y[0] {
			allSame = false
			break
		}
	}
	if allSame || depth >= rf.maxDepth {
		// Majority vote
		count := 0
		for _, label := range y {
			count += label
		}
		pred := 0
		if count > len(y)/2 {
			pred = 1
		}
		return &DecisionTree{isLeaf: true, prediction: pred}
	}

	// Find best split over a random feature subset (mtry).
	bestFeature, bestThreshold, bestGain := rf.findBestSplit(X, y, mtry, rng)
	if bestGain <= 0 {
		count := 0
		for _, label := range y {
			count += label
		}
		pred := 0
		if count > len(y)/2 {
			pred = 1
		}
		return &DecisionTree{isLeaf: true, prediction: pred}
	}

	// Split data
	leftX, leftY, rightX, rightY := splitData(X, y, bestFeature, bestThreshold)

	node := &DecisionTree{
		featureIdx: bestFeature,
		threshold:  bestThreshold,
	}
	node.left = rf.buildTree(leftX, leftY, depth+1, mtry, rng)
	node.right = rf.buildTree(rightX, rightY, depth+1, mtry, rng)

	return node
}

func (rf *RandomForest) findBestSplit(X [][]float64, y []int, mtry int, rng *rand.Rand) (int, float64, float64) {
	bestFeature := 0
	bestThreshold := 0.0
	bestGain := -1.0

	nFeatures := len(X[0])
	currentGini := gini(y)
	candidates := sampleFeatures(nFeatures, mtry, rng)
	n := len(y)

	for _, feature := range candidates {
		// Sort row indices once and scan all distinct cut points with prefix
		// class counts. The previous implementation rebuilt left/right slices
		// for every threshold, making a node O(n^2) for each feature.
		order := make([]int, n)
		for i := range order {
			order[i] = i
		}
		sort.SliceStable(order, func(i, j int) bool {
			return X[order[i]][feature] < X[order[j]][feature]
		})

		leftOnes := 0
		totalOnes := 0
		for _, label := range y {
			if label == 1 {
				totalOnes++
			}
		}
		for i := 0; i < n-1; i++ {
			if y[order[i]] == 1 {
				leftOnes++
			}
			if X[order[i]][feature] == X[order[i+1]][feature] {
				continue
			}

			leftN := i + 1
			rightN := n - leftN
			rightOnes := totalOnes - leftOnes
			leftP := float64(leftOnes) / float64(leftN)
			rightP := float64(rightOnes) / float64(rightN)
			leftGini := 1 - leftP*leftP - (1-leftP)*(1-leftP)
			rightGini := 1 - rightP*rightP - (1-rightP)*(1-rightP)
			weightedGini := float64(leftN)/float64(n)*leftGini +
				float64(rightN)/float64(n)*rightGini
			gain := currentGini - weightedGini
			if gain > bestGain {
				bestGain = gain
				bestFeature = feature
				bestThreshold = (X[order[i]][feature] + X[order[i+1]][feature]) / 2.0
			}
		}
	}

	return bestFeature, bestThreshold, bestGain
}

func (rf *RandomForest) predictTree(node *DecisionTree, features []float64) int {
	if node.isLeaf {
		return node.prediction
	}

	if features[node.featureIdx] <= node.threshold {
		return rf.predictTree(node.left, features)
	}
	return rf.predictTree(node.right, features)
}

// Helper functions

// bootstrapSample draws `n` examples with replacement using `rng`. This is
// the bagging step of bagged decision trees: each tree sees a different
// resampled view of the training set, which is what makes the ensemble's
// predictions decorrelate. The previous implementation used `idx := i`,
// effectively giving every tree the same data — so the "forest" collapsed
// to a single deterministic tree. Restored here.
func bootstrapSample(X [][]float64, y []int, rng *rand.Rand) ([][]float64, []int) {
	n := len(X)
	bootX := make([][]float64, n)
	bootY := make([]int, n)

	for i := 0; i < n; i++ {
		idx := rng.Intn(n)
		bootX[i] = X[idx]
		bootY[i] = y[idx]
	}

	return bootX, bootY
}

// sampleFeatures draws `k` distinct feature indices from [0, nFeatures) using
// a partial Fisher-Yates shuffle. Allocation-light: O(nFeatures) for the
// permutation buffer, O(k) for the output. For typical k = √n this is
// negligible compared to the threshold scan inside findBestSplit.
func sampleFeatures(nFeatures, k int, rng *rand.Rand) []int {
	if k >= nFeatures {
		out := make([]int, nFeatures)
		for i := range out {
			out[i] = i
		}
		return out
	}
	perm := make([]int, nFeatures)
	for i := range perm {
		perm[i] = i
	}
	for i := 0; i < k; i++ {
		j := i + rng.Intn(nFeatures-i)
		perm[i], perm[j] = perm[j], perm[i]
	}
	return perm[:k]
}

func gini(y []int) float64 {
	if len(y) == 0 {
		return 0
	}

	count := 0
	for _, label := range y {
		count += label
	}

	p1 := float64(count) / float64(len(y))
	p0 := 1 - p1

	return 1 - p0*p0 - p1*p1
}

func getThresholds(X [][]float64, feature int) []float64 {
	// Get sorted unique values
	values := make(map[float64]bool)
	for _, row := range X {
		values[row[feature]] = true
	}

	thresholds := make([]float64, 0, len(values))
	for v := range values {
		thresholds = append(thresholds, v)
	}
	// Sort ascending so the threshold scan is deterministic across runs.
	// Without this, map iteration order plus tie-equal gains would let the
	// "best" split flip non-deterministically — fatal for reproducible RFs
	// and for any test that pins a seed.
	sort.Float64s(thresholds)

	return thresholds
}

func splitData(X [][]float64, y []int, feature int, threshold float64) ([][]float64, []int, [][]float64, []int) {
	var leftX, rightX [][]float64
	var leftY, rightY []int

	for i := range X {
		if X[i][feature] <= threshold {
			leftX = append(leftX, X[i])
			leftY = append(leftY, y[i])
		} else {
			rightX = append(rightX, X[i])
			rightY = append(rightY, y[i])
		}
	}

	return leftX, leftY, rightX, rightY
}
