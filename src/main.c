#include <capstone/capstone.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "pe/context.h"
#include "trace.h"
#include "graph.h"

int
main (int argc, const char* argv[])
{
  if (argc < 2)
    $abort ("usage: %s <path-to-image>", argv[0]);

  auto file = fopen (argv[1], "rb");
  if (file == NULL)
    $abort ("failed to open path: %s", argv[1]);
  $trace_debug ("file opened: %s", argv[1]);

  auto pe_context = pe$from_file (
    file, PE_CONTEXT_LOAD_IMPORT_DIRECTORY | PE_CONTEXT_LOAD_EXPORT_DIRECTORY
      | PE_CONTEXT_LOAD_TLS_DIRECTORY);
  if (pe_context == NULL)
    $abort ("failed to create PE context from file");

  auto graph = graph$new ();


  auto node_1 = graph$add (graph, "Node 1");
  auto node_2 = graph$add (graph, "Node 2");

  digraph$connect (graph, node_1, node_2);

  auto node_2_ingress = digraph$get_ingress (graph, node_2);
  $array_for_each ($, node_2_ingress, vertex_tag_t, tag)
  {
    const char* metadata = graph$metadata (graph, *$.tag);
    $trace_debug ("Node connected to Node 2: %s", metadata);
  }
  array$free (node_2_ingress);

  graph$free (graph);

  pe$free (pe_context);
  fclose (file);
  return EXIT_SUCCESS;
}