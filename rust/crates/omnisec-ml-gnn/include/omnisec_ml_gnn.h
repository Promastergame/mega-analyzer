#ifndef OMNISEC_ML_GNN_H
#define OMNISEC_ML_GNN_H

#include <stdint.h>

typedef struct {
    uint64_t* row_ptrs;
    uint64_t  row_ptrs_len;
    uint64_t* col_indices;
    uint64_t  col_indices_len;
    uint32_t* edge_types;
    uint64_t  edge_types_len;
    float*    node_features;
    uint64_t  num_nodes;
    uint64_t  feature_dim;
} ffi_graph_tensor_t;

void*  gnn_model_load(const char* path);
void   gnn_model_free(void* model);
float* gnn_model_infer(void* model, ffi_graph_tensor_t* graph, uint64_t* out_classes);
void   gnn_free_result(float* result);

#endif
