#include "graph.h"
#include "array.h"
#include "map.h"
#include <stdbool.h>

struct graph_vertex
{
  vertex_tag_t tag;
  void* metadata;
};

struct _graph
{
  map_t /* vertex-tag -> array[vertex-tag] */ map_vertex_edges;
  array_t /* struct graph_vertex */ vertices;
  vertex_tag_t tag_counter;
};

static struct graph_vertex*
get_vertex (graph_t graph, vertex_tag_t tag)
{
  $array_for_each ($, graph->vertices, struct graph_vertex, vertex)
  {
    if ($.vertex->tag == tag)
      return $.vertex;
  }
  return NULL;
}

static array_t
get_vertex_edges (graph_t graph, vertex_tag_t tag)
{
  array_t edges = map$get (graph->map_vertex_edges, tag);
  $strict_assert (edges != NULL, "No edge array for vertex");
  return edges;
}

graph_t
graph$new (void)
{
  $trace_debug ("allocating graph");
  auto graph = $chk_allocty (graph_t);
  graph->map_vertex_edges = map$new ();
  graph->vertices = array$new (sizeof (struct graph_vertex));
  array$allocopts (graph->vertices, (struct array_allocopts){
    .alloc_nmemb_increment = 1,
    .trim_nmemb_threshold = 1
  });
  return graph;
}

static bool
iter_vertex_edges_free (void* data, hashnum_t key, void* value)
{
  (void)data; (void)key;
  array_t edges = value;
  array$free (edges);
  return true;
}

void
graph$free (graph_t graph)
{
  $trace_debug ("freeing graph");
  array$free (graph->vertices);
  map$for_each_pair (graph->map_vertex_edges, iter_vertex_edges_free, NULL);
  map$free (graph->map_vertex_edges);
  $chk_free (graph);
}

vertex_tag_t
graph$add (graph_t graph, void* metadata)
{
  auto tag = graph->tag_counter++;
  $trace_debug ("adding new node with tag %zu", tag);
  struct graph_vertex vertex = { .metadata = metadata, .tag = tag};
  array$append (graph->vertices, &vertex);
  auto edges = array$new (sizeof (vertex_tag_t));
  map$set (graph->map_vertex_edges, tag, edges);
  return tag;
}

vertex_tag_t
graph$add_tagged (graph_t graph, vertex_tag_t tag, void* metadata)
{
  $trace_debug ("adding new node with preset tag %zu", tag);
#ifdef STRICT
  $array_for_each ($, graph->vertices, struct graph_vertex, vertex)
  {
    if ($.vertex->tag == tag)
      $abort ("preset tag already exists in vertices");
  }
#endif
  struct graph_vertex vertex = { .metadata = metadata, .tag = tag };
  array$append (graph->vertices, &vertex);
  auto edges = array$new (sizeof (vertex_tag_t));
  map$set (graph->map_vertex_edges, tag, edges);
  return tag;
}

void
digraph$connect (graph_t graph, vertex_tag_t a, vertex_tag_t b)
{
  $strict_assert (
    (get_vertex (graph, a) != NULL) 
    && (get_vertex (graph, b) != NULL),
    "Invalid vertex tags");
  array_t edges = get_vertex_edges (graph, a);
  $strict_assert (
    !array$contains (edges, &b),
    "Vertex cannot connect to another more than once");
  $trace_debug ("connected node %zu to node %zu", a, b);
  array$append (edges, &b);
}

void
graph$connect (graph_t graph, vertex_tag_t a, vertex_tag_t b)
{
  digraph$connect (graph, a, b);
  digraph$connect (graph, b, a);
}

array_t
digraph$get_egress (graph_t graph, vertex_tag_t tag)
{
  return get_vertex_edges (graph, tag);
}

struct iter_get_ingress_param
{
  array_t ingress_array;
  vertex_tag_t comparand;
};

static bool
iter_get_ingress (void* data, hashnum_t key, void* value)
{
  struct iter_get_ingress_param* param = data;
  array_t edges = value;
  $array_for_each ($, edges, vertex_tag_t, tag)
  {
    if (*$.tag == param->comparand)
      array$append (param->ingress_array, &key);
  }
  return true;
}

array_t
digraph$get_ingress (graph_t graph, vertex_tag_t tag)
{
  struct iter_get_ingress_param param = {
    .ingress_array = array$new (sizeof (vertex_tag_t)),
    .comparand = tag
  };
  map$for_each_pair (graph->map_vertex_edges, iter_get_ingress, &param);
  return param.ingress_array;
}

array_t
graph$get_edges (graph_t graph, vertex_tag_t tag)
{
  array_t ingress = digraph$get_ingress (graph, tag);
  array$concat (ingress, digraph$get_egress (graph, tag));
  return ingress;
}

void
digraph$disconnect (graph_t graph, vertex_tag_t a, vertex_tag_t b)
{
  $trace_debug ("disconnecting node %zu from node %zu", a, b);
  auto edges = get_vertex_edges (graph, a);
  $array_for_each ($, edges, vertex_tag_t, tag)
  {
    if (*$.tag == b)
    {
      array$remove (edges, $.i);
      break;
    }
  }
}

void
graph$disconnect (graph_t graph, vertex_tag_t a, vertex_tag_t b)
{
  digraph$disconnect (graph, a, b);
  digraph$disconnect (graph, b, a);
}

void*
graph$metadata (graph_t graph, vertex_tag_t tag)
{
  return get_vertex (graph, tag)->metadata;
}

bool
graph$for_each_vertex (graph_t graph, iter_vertex_t callback, void* param)
{
  $array_for_each ($, graph->vertices, struct graph_vertex, vertex)
  {
    if (!callback ($.vertex->tag, $.vertex->metadata, param))
      return true;
  }
  return false;
}