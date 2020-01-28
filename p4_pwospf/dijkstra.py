from collections import defaultdict
from itertools import combinations

def build_graph(edge_list):
    graph = defaultdict(list)
    seen_edges = defaultdict(int)
    for src, dst, weight in edge_list:
        seen_edges[(src, dst, weight)] += 1
        if seen_edges[(src, dst, weight)] > 1:  # checking for duplicated edge entries
            continue
        graph[src].append((dst, weight))
        graph[dst].append((src, weight))  # remove this line of edge list is directed
    return graph


def dijkstra(graph, src, dst=None):
    nodes = []
    for n in graph:
        nodes.append(n)
        nodes += [x[0] for x in graph[n]]

    q = set(nodes)
    nodes = list(q)
    dist = dict()
    prev = dict()
    for n in nodes:
        dist[n] = float('inf')
        prev[n] = None

    dist[src] = 0

    while q:
        u = min(q, key=dist.get)
        q.remove(u)

        if dst is not None and u == dst:
            return dist[dst], prev

        for v, w in graph.get(u, ()):
            alt = dist[u] + w
            if alt < dist[v]:
                dist[v] = alt
                prev[v] = u

    return dist, prev


def find_path(pr, node):  # generate path list based on parent points 'prev'
    p = []
    print pr, node
    while node is not None:
        p.append(node)
        node = pr[node]
    return p[::-1]

def get_shortest_path(rid, links):
    links_dict = defaultdict(list)

    for link in links:
        links_dict[link[1]].append(link[3])
    print links_dict
    edges = []
    for key, value in links_dict.items():
        for combination in list(combinations(value, 2)):
            edges.append((combination[0], combination[1], 1))

    print edges, links

    g = build_graph(edges)

    src = rid
    dst = '0.0.0.0'
    d, prev = dijkstra(g, src, dst)
    path = find_path(prev, dst)
    #print("1 -> 4: distance = {}, path = {}".format(d, path))
    next_hop = path[1]
    #return next_hop
    for key, value in links_dict.items():
        if(src in value and next_hop in value):
            return key #subnet
