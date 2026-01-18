#pragma once

#include "generic.h"
#include "array.h"

typedef struct _graph *graph_t;
typedef uint64_t vertex_tag_t;
typedef bool (*iter_vertex_t)(vertex_tag_t tag, void* metadata, void* param);

void graph$free (graph_t);

__attribute__ (( malloc(graph$free, 1) ))
graph_t graph$new (void);

vertex_tag_t graph$add (graph_t, void* metadata);
vertex_tag_t graph$add_tagged (graph_t, vertex_tag_t tag, void* metadata);
void digraph$connect (graph_t, vertex_tag_t, vertex_tag_t);
array_t digraph$get_egress (graph_t, vertex_tag_t);
__attribute__(( malloc(array$free, 1) ))
array_t digraph$get_ingress (graph_t, vertex_tag_t);
__attribute__(( malloc(array$free, 1) ))
array_t graph$get_edges (graph_t, vertex_tag_t);
void graph$connect (graph_t, vertex_tag_t, vertex_tag_t);
void graph$disconnect (graph_t, vertex_tag_t, vertex_tag_t);
void digraph$disconnect (graph_t, vertex_tag_t, vertex_tag_t);
void* graph$metadata (graph_t, vertex_tag_t);
bool graph$for_each_vertex (graph_t, iter_vertex_t callback, void* param);