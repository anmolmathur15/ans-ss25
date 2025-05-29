"""
 Copyright (c) 2025 Computer Networks Group @ UPB

 Permission is hereby granted, free of charge, to any person obtaining a copy of
 this software and associated documentation files (the "Software"), to deal in
 the Software without restriction, including without limitation the rights to
 use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 the Software, and to permit persons to whom the Software is furnished to do so,
 subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 """

# Class for an edge in the graph
class Edge:
    def __init__(self):
        self.lnode = None
        self.rnode = None
    
    def remove(self):
        self.lnode.edges.remove(self)
        self.rnode.edges.remove(self)
        self.lnode = None
        self.rnode = None

# Class for a node in the graph
class Node:
    def __init__(self, id, type):
        self.edges = []
        self.id = id
        self.type = type

    # Add an edge connected to another node
    def add_edge(self, node):
        edge = Edge()
        edge.lnode = self
        edge.rnode = node
        self.edges.append(edge)
        node.edges.append(edge)
        return edge

    # Remove an edge from the node
    def remove_edge(self, edge):
        self.edges.remove(edge)

    # Decide if another node is a neighbor
    def is_neighbor(self, node):
        for edge in self.edges:
            if edge.lnode == node or edge.rnode == node:
                return True
        return False


class Fattree:

    def __init__(self, num_ports):
        self.servers = []
        self.switches = []
        self.generate(num_ports)

    def generate(self, num_ports):

        # TODO: code for generating the fat-tree topology
        k = num_ports
        pods = k
        num_edge = k // 2
        num_agg  = k // 2

        # keep track of every edge in the graph
        self.edges = []
    
        # --- Core layer ---
        # build a (num_agg x num_agg) grid of core switches
        core = []
        for grp in range(num_agg):
            row = []
            for j in range(num_agg):
                sw = Node(f"s{len(self.switches)}", type="switch")
                self.switches.append(sw)
                row.append(sw)
            core.append(row)

        # --- Pod layer ---
        for pod in range(pods):
            agg_switches = []
            edge_switches = []

            # aggregation switches in this pod
            for i in range(num_agg):
                sw = Node(f"s{len(self.switches)}", type="switch")
                self.switches.append(sw)
                agg_switches.append(sw)

            # edge switches in this pod
            for i in range(num_edge):
                sw = Node(f"s{len(self.switches)}", type="switch")
                self.switches.append(sw)
                edge_switches.append(sw)

            # connect each edge switch to its k/2 hosts
            for ei, edge_sw in enumerate(edge_switches):
                for h in range(num_edge):
                    host = Node(f"h{pod}_{ei}_{h}", type="server")
                    # assign the fat-tree IP: 10.pod.edge_index.host_index
                    host.ip = f"10.{pod}.{ei}.{h+1}/24"
                    self.servers.append(host)
                    e = host.add_edge(edge_sw)
                    self.edges.append(e)

            # connect edge → agg within this pod
            for edge_sw in edge_switches:
                for agg_sw in agg_switches:
                    e = edge_sw.add_edge(agg_sw)
                    self.edges.append(e)

            # connect agg → core: agg[i] to core group-rows at column i
            for ai, agg_sw in enumerate(agg_switches):
                for grp in range(num_agg):
                    core_sw = core[grp][ai]
                    e = agg_sw.add_edge(core_sw)
                    self.edges.append(e)
