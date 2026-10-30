package ml

import (
	"errors"
	"fmt"
	"math"
	"math/rand"
	"sort"
)

// ═══════════════════════════════════════════════════════════════════════════
// GRADIENT BOOSTED TREES — binary classification with log-loss
// ═══════════════════════════════════════════════════════════════════════════
//
// Pure-Go implementation of standard gradient boosted regression trees on
// log-loss residuals (a.k.a. "logistic GBT" or LogitBoost-style fitting).
// No external dependency: stdlib math + math/rand only.
//
// Each round we:
//   1. Compute pseudo-residuals  r_i = y_i − sigmoid(F(x_i))
//      where F is the running ensemble's raw score (logit).
//   2. Fit a regression tree to (X, r).
//   3. Add the tree to the ensemble with weight `learningRate`.
//   4. Optionally evaluate held-out validation log-loss for early stopping.
//
// Why GBT instead of just fixing the existing RF:
//   - GBT typically beats RF on imbalanced security data because each round
//     focuses on the examples the current ensemble gets wrong (residuals).
//   - Smaller trees (depth 3–6) are sufficient — faster training and fewer
//     overfit failure modes than deep RF trees.
//   - Probability calibration is better out of the box: F(x) is a logit, so
//     sigmoid(F(x)) is a valid probability without Platt scaling.

// regNode is a node in a regression tree. Same shape as DecisionTree but
// the leaf payload is a float (the mean residual that fell into this leaf,
// then turned into a Newton step in the GBT loop).
type regNode struct {
	featureIdx int
	threshold  float64
	left       *regNode
	right      *regNode
	value      float64 // leaf prediction (float)
	isLeaf     bool
}

// regTreeConfig pins the per-tree hyperparameters.
type regTreeConfig struct {
	maxDepth        int
	minSamplesSplit int
	maxFeatures     int // mtry — same role as in RF
	rng             *rand.Rand

	// presort optionally holds, for each feature, the global row indices sorted
	// ascending by that feature (stable). When set, split search filters this
	// order by the current node's membership instead of re-sorting every node,
	// turning per-node O(n log n) sorting into O(N) scans. Results are identical
	// to the copy+stable-sort path because both preserve original index order on
	// ties. nRows is the width of the membership buffer.
	presort [][]int
	nRows   int
}

// fitRegressionTree builds a regression tree on (X, residuals) using
// variance-reduction splits. Indices `idx` are the row indices to consider
// (used so we don't reslice the matrix at every recursion).
func fitRegressionTree(X [][]float64, residuals []float64, idx []int, depth int, cfg *regTreeConfig) *regNode {
	// Base cases.
	if len(idx) == 0 {
		return &regNode{isLeaf: true, value: 0}
	}
	if depth >= cfg.maxDepth || len(idx) < cfg.minSamplesSplit {
		return &regNode{isLeaf: true, value: meanOf(residuals, idx)}
	}

	bestFeat, bestThr, bestGain := bestRegressionSplit(X, residuals, idx, cfg)
	if bestGain <= 0 || bestFeat < 0 {
		return &regNode{isLeaf: true, value: meanOf(residuals, idx)}
	}

	leftIdx := make([]int, 0, len(idx)/2)
	rightIdx := make([]int, 0, len(idx)/2)
	for _, i := range idx {
		if X[i][bestFeat] <= bestThr {
			leftIdx = append(leftIdx, i)
		} else {
			rightIdx = append(rightIdx, i)
		}
	}
	if len(leftIdx) == 0 || len(rightIdx) == 0 {
		return &regNode{isLeaf: true, value: meanOf(residuals, idx)}
	}

	return &regNode{
		featureIdx: bestFeat,
		threshold:  bestThr,
		left:       fitRegressionTree(X, residuals, leftIdx, depth+1, cfg),
		right:      fitRegressionTree(X, residuals, rightIdx, depth+1, cfg),
	}
}

// bestRegressionSplit finds the (feature, threshold) pair that maximises
// variance reduction. Same structure as the classification version, but
// scoring uses sum-of-squares (equivalent to MSE) instead of Gini.
func bestRegressionSplit(X [][]float64, residuals []float64, idx []int, cfg *regTreeConfig) (int, float64, float64) {
	if len(idx) < 2 {
		return -1, 0, 0
	}
	nFeatures := len(X[0])
	mtry := cfg.maxFeatures
	if mtry == 0 {
		mtry = int(math.Floor(math.Sqrt(float64(nFeatures))))
	}
	if mtry < 1 {
		mtry = 1
	}
	if mtry > nFeatures {
		mtry = nFeatures
	}
	candidates := sampleFeatures(nFeatures, mtry, cfg.rng)

	parentSum := float64(0)
	for _, i := range idx {
		parentSum += residuals[i]
	}
	n := float64(len(idx))

	bestFeat, bestThr, bestGain := -1, 0.0, 0.0

	// Membership buffer for the presort fast path. Marks rows in this node.
	var member []bool
	if cfg.presort != nil && cfg.nRows > 0 {
		member = make([]bool, cfg.nRows)
		for _, i := range idx {
			member[i] = true
		}
	}

	for _, feat := range candidates {
		// Obtain node indices sorted by this feature. Prefer the presort fast
		// path (filter global order by membership); fall back to copy+sort.
		var sorted []int
		if member != nil {
			sorted = make([]int, 0, len(idx))
			for _, i := range cfg.presort[feat] {
				if member[i] {
					sorted = append(sorted, i)
				}
			}
		} else {
			sorted = make([]int, len(idx))
			copy(sorted, idx)
			sortByFeature(sorted, X, feat)
		}

		var leftSum float64
		for k := 0; k < len(sorted)-1; k++ {
			leftSum += residuals[sorted[k]]
			// Skip splits with identical feature values: they can't separate.
			if X[sorted[k]][feat] == X[sorted[k+1]][feat] {
				continue
			}
			leftN := float64(k + 1)
			rightN := n - leftN
			rightSum := parentSum - leftSum

			// Variance reduction, via the sum-of-squares identity:
			//   gain ∝ leftSum²/leftN + rightSum²/rightN − parentSum²/n
			//
			// The parent term is not optional. Dropping it shifts every gain by
			// the same constant, which indeed leaves the argmax alone — but the
			// caller rejects a split on `bestGain <= 0`, and without the
			// subtraction the quantity is non-negative for every possible
			// split. That stopping rule therefore never fired and trees grew to
			// maxDepth on pure noise.
			gain := (leftSum*leftSum)/leftN + (rightSum*rightSum)/rightN - (parentSum*parentSum)/n
			if gain > bestGain {
				bestGain = gain
				bestFeat = feat
				bestThr = (X[sorted[k]][feat] + X[sorted[k+1]][feat]) / 2.0
			}
		}
	}
	return bestFeat, bestThr, bestGain
}

func predictRegressionTree(node *regNode, x []float64) float64 {
	for !node.isLeaf {
		if x[node.featureIdx] <= node.threshold {
			node = node.left
		} else {
			node = node.right
		}
	}
	return node.value
}

func meanOf(residuals []float64, idx []int) float64 {
	if len(idx) == 0 {
		return 0
	}
	var s float64
	for _, i := range idx {
		s += residuals[i]
	}
	return s / float64(len(idx))
}

func varianceOf(residuals []float64, idx []int) float64 {
	if len(idx) == 0 {
		return 0
	}
	m := meanOf(residuals, idx)
	var s float64
	for _, i := range idx {
		d := residuals[i] - m
		s += d * d
	}
	return s / float64(len(idx))
}


// buildPresort returns, for each feature column, the row indices sorted
// ascending (stable) by that feature. Computed once and shared across all
// trees so per-node split search never re-sorts.
func buildPresort(X [][]float64) [][]int {
	if len(X) == 0 || len(X[0]) == 0 {
		return nil
	}
	nRows := len(X)
	nFeat := len(X[0])
	presort := make([][]int, nFeat)
	for f := 0; f < nFeat; f++ {
		order := make([]int, nRows)
		for i := range order {
			order[i] = i
		}
		sort.SliceStable(order, func(a, b int) bool {
			return X[order[a]][f] < X[order[b]][f]
		})
		presort[f] = order
	}
	return presort
}

// sortByFeature performs an in-place ascending sort of idx by X[i][feat].
// The previous insertion sort degraded to O(n²) at the root of large trees;
// the standard-library sort keeps split search at O(n log n) per candidate.
func sortByFeature(idx []int, X [][]float64, feat int) {
	sort.SliceStable(idx, func(i, j int) bool {
		return X[idx[i]][feat] < X[idx[j]][feat]
	})
}

// GradientBoostingClassifier is a binary log-loss GBT.
type GradientBoostingClassifier struct {
	NEstimators     int
	LearningRate    float64
	MaxDepth        int
	MinSamplesSplit int
	MaxFeatures     int     // 0 → √n
	Subsample       float64 // row sampling per tree, in (0, 1]; 1.0 = no sampling
	Seed            int64

	// Early stopping. When ValidationFraction > 0 and EarlyStoppingRounds > 0,
	// we hold out a stratified fraction and stop training once held-out log-
	// loss fails to improve for `EarlyStoppingRounds` consecutive rounds.
	ValidationFraction  float64
	EarlyStoppingRounds int
	Tol                 float64

	// Filled in by Fit().
	initLogit    float64
	trees        []*regNode
	featureNames []string
	// nFeatures is the training-time vector width. featureNames is optional,
	// so it cannot serve as the length contract on its own.
	nFeatures        int
	trained          bool
	BestIteration    int // index of the best round when early stopping kicked in
	TrainLossHistory []float64
	ValLossHistory   []float64
}

// DefaultGradientBoosting returns a GBT pre-tuned for the security-triage
// regime: shallow trees, modest learning rate, light row sampling, and
// early stopping on a held-out 20%.
func DefaultGradientBoosting() *GradientBoostingClassifier {
	return &GradientBoostingClassifier{
		NEstimators:         200,
		LearningRate:        0.1,
		MaxDepth:            4,
		MinSamplesSplit:     2,
		MaxFeatures:         0,
		Subsample:           0.8,
		Seed:                0,
		ValidationFraction:  0.2,
		EarlyStoppingRounds: 15,
		Tol:                 1e-5,
	}
}

// Fit trains the ensemble.
func (g *GradientBoostingClassifier) Fit(X [][]float64, y []int, featureNames []string) error {
	if len(X) != len(y) {
		return fmt.Errorf("X and y must have same length")
	}
	if len(X) == 0 {
		return errors.New("training data cannot be empty")
	}
	g.featureNames = featureNames
	g.nFeatures = len(X[0])
	g.trees = g.trees[:0]
	g.TrainLossHistory = g.TrainLossHistory[:0]
	g.ValLossHistory = g.ValLossHistory[:0]
	g.trained = false

	masterSeed := g.Seed
	if masterSeed == 0 {
		masterSeed = rand.Int63()
	}
	rng := rand.New(rand.NewSource(masterSeed))

	// Stratified train/validation split. We do it deterministically wrt the
	// PRNG so users with the same Seed get identical hold-outs.
	trainIdx, valIdx := g.splitTrainVal(y, rng)

	// Initial prediction = log-odds of the training prior. This is the
	// optimal constant predictor under log-loss.
	posCount := 0
	for _, i := range trainIdx {
		if y[i] == 1 {
			posCount++
		}
	}
	frac := float64(posCount) / float64(len(trainIdx))
	const eps = 1e-12
	frac = math.Max(eps, math.Min(1.0-eps, frac))
	g.initLogit = math.Log(frac / (1.0 - frac))

	// Running raw scores F(x_i) for every training row.
	rawScores := make([]float64, len(X))
	for i := range rawScores {
		rawScores[i] = g.initLogit
	}

	mtry := g.MaxFeatures
	if mtry == 0 {
		mtry = int(math.Floor(math.Sqrt(float64(len(X[0])))))
	}

	bestVal := math.Inf(1)
	stagnant := 0

	// Precompute per-feature global sort order once, reused by every tree/node.
	presort := buildPresort(X)

	for iter := 0; iter < g.NEstimators; iter++ {
		// Pseudo-residuals = y − sigmoid(F).
		residuals := make([]float64, len(X))
		for _, i := range trainIdx {
			residuals[i] = float64(y[i]) - sigmoid(rawScores[i])
		}

		// Row subsampling (stochastic GB).
		var sampleIdx []int
		if g.Subsample < 1.0 && g.Subsample > 0 {
			n := int(math.Round(float64(len(trainIdx)) * g.Subsample))
			if n < 1 {
				n = 1
			}
			perm := append([]int(nil), trainIdx...)
			rng.Shuffle(len(perm), func(i, j int) { perm[i], perm[j] = perm[j], perm[i] })
			sampleIdx = perm[:n]
		} else {
			sampleIdx = trainIdx
		}

		treeRng := rand.New(rand.NewSource(rng.Int63()))
		mss := g.MinSamplesSplit
		if mss < 2 {
			mss = 2
		}
		cfg := &regTreeConfig{
			maxDepth:        g.MaxDepth,
			minSamplesSplit: mss,
			maxFeatures:     mtry,
			rng:             treeRng,
			presort:         presort,
			nRows:           len(X),
		}
		tree := fitRegressionTree(X, residuals, sampleIdx, 0, cfg)
		g.trees = append(g.trees, tree)

		// Update running scores on every training row.
		for _, i := range trainIdx {
			rawScores[i] += g.LearningRate * predictRegressionTree(tree, X[i])
		}

		// Track losses.
		trainLoss := computeLogLossOnIndex(rawScores, y, trainIdx)
		g.TrainLossHistory = append(g.TrainLossHistory, trainLoss)

		if len(valIdx) > 0 {
			// Need to score validation rows too — they aren't in rawScores
			// because we only ever updated train indices there, so compute
			// from scratch each round (cheap: F is sum over trees).
			valLoss := g.computeValLoss(X, y, valIdx)
			g.ValLossHistory = append(g.ValLossHistory, valLoss)

			if valLoss+g.Tol < bestVal {
				bestVal = valLoss
				g.BestIteration = iter
				stagnant = 0
			} else {
				stagnant++
				if g.EarlyStoppingRounds > 0 && stagnant >= g.EarlyStoppingRounds {
					// Trim trees back to the best iteration so prediction
					// uses only the validated subset.
					g.trees = g.trees[:g.BestIteration+1]
					break
				}
			}
		} else {
			g.BestIteration = iter
		}
	}

	g.trained = true
	return nil
}

// splitTrainVal returns stratified train/val index slices.
func (g *GradientBoostingClassifier) splitTrainVal(y []int, rng *rand.Rand) ([]int, []int) {
	if g.ValidationFraction <= 0 || g.EarlyStoppingRounds <= 0 {
		all := make([]int, len(y))
		for i := range all {
			all[i] = i
		}
		return all, nil
	}

	pos, neg := []int{}, []int{}
	for i, lbl := range y {
		if lbl == 1 {
			pos = append(pos, i)
		} else {
			neg = append(neg, i)
		}
	}
	rng.Shuffle(len(pos), func(i, j int) { pos[i], pos[j] = pos[j], pos[i] })
	rng.Shuffle(len(neg), func(i, j int) { neg[i], neg[j] = neg[j], neg[i] })

	nPosVal := int(math.Round(g.ValidationFraction * float64(len(pos))))
	nNegVal := int(math.Round(g.ValidationFraction * float64(len(neg))))
	if nPosVal == 0 && len(pos) > 1 {
		nPosVal = 1
	}
	if nNegVal == 0 && len(neg) > 1 {
		nNegVal = 1
	}

	// Build val/train with fresh backing arrays. `pos`/`neg` were grown via
	// append() in the loop above, so they can have spare capacity; naively
	// appending neg[...] directly onto pos[:nPosVal] (or pos[nPosVal:])
	// would write into pos's shared backing array and silently corrupt
	// whichever slice (train or val) is read from pos afterwards, causing
	// train/validation leakage. Always copy into new slices instead.
	val := make([]int, 0, nPosVal+nNegVal)
	val = append(val, pos[:nPosVal]...)
	val = append(val, neg[:nNegVal]...)
	train := make([]int, 0, (len(pos)-nPosVal)+(len(neg)-nNegVal))
	train = append(train, pos[nPosVal:]...)
	train = append(train, neg[nNegVal:]...)
	return train, val
}

func (g *GradientBoostingClassifier) computeValLoss(X [][]float64, y []int, idx []int) float64 {
	const eps = 1e-12
	var loss float64
	for _, i := range idx {
		p := sigmoid(g.rawScore(X[i]))
		p = math.Max(eps, math.Min(1.0-eps, p))
		if y[i] == 1 {
			loss -= math.Log(p)
		} else {
			loss -= math.Log(1.0 - p)
		}
	}
	return loss / float64(len(idx))
}

func computeLogLossOnIndex(rawScores []float64, y []int, idx []int) float64 {
	const eps = 1e-12
	var loss float64
	for _, i := range idx {
		p := sigmoid(rawScores[i])
		p = math.Max(eps, math.Min(1.0-eps, p))
		if y[i] == 1 {
			loss -= math.Log(p)
		} else {
			loss -= math.Log(1.0 - p)
		}
	}
	return loss / float64(len(idx))
}

// rawScore returns the unsquashed ensemble score F(x).
func (g *GradientBoostingClassifier) rawScore(x []float64) float64 {
	score := g.initLogit
	for _, t := range g.trees {
		score += g.LearningRate * predictRegressionTree(t, x)
	}
	return score
}

// PredictProbability returns sigmoid(F(x)).
//
// The length check is exact. The previous version only rejected empty vectors
// and ones more than twice the expected width, so a SHORT vector passed
// validation and then panicked with index-out-of-range inside the tree walk,
// where the failure is far from its cause.
func (g *GradientBoostingClassifier) PredictProbability(x []float64) (float64, error) {
	if !g.trained {
		return 0, errors.New("model not trained yet")
	}
	if g.nFeatures > 0 && len(x) != g.nFeatures {
		return 0, fmt.Errorf("feature vector has length %d, model expects %d", len(x), g.nFeatures)
	}
	if len(x) == 0 {
		return 0, errors.New("empty feature vector")
	}
	return sigmoid(g.rawScore(x)), nil
}

// Predict returns the thresholded class label at p ≥ 0.5.
func (g *GradientBoostingClassifier) Predict(x []float64) (int, error) {
	p, err := g.PredictProbability(x)
	if err != nil {
		return 0, err
	}
	if p >= 0.5 {
		return 1, nil
	}
	return 0, nil
}
