from collections import defaultdict, OrderedDict
import pandas as pd
import sys, os, re
import glob, json


def printTree(dic):
    for key, val in dic.items():
        print(key)
        print(val)
        print("*****************************************************************************")

def buildGraph(df_both):
    parent2children = defaultdict(list) # caller:[a list of callees]
    child2parents = defaultdict(list) # callee:[a list of callers]
    n = len(df_both)

    for i in range(n):
        caller, callee = df_both.iloc[i, :]
        caller = caller.split('/')[0][1:-1]
        callee = callee[1:-1]
        parent2children[caller].append(callee)
        child2parents[callee].append(caller)
    return parent2children,child2parents

def dfs(node, statusMap, cb):
    if statusMap[node] != 0:
        if statusMap[node] == 1:
            print("recursive on %s!" % node )
        return
    cb(node)
    statusMap[node] = 1
    # if node not in graph_dic:
    #     res.add(node)
    # else:
    for adjacent in graph_dic[node]:
        dfs(adjacent)
    statusMap[node] = 2

def getSensitiveEvents(filename):
    events = {}
    with open(filename) as file:
        for line in file:
            line = line[:-1].split("->")
            line[0] = line[0][25:].replace("/",".")
            events[line[0]] = [line[0].split(":")[1],line[1]]
    return events

def getAllPath(dic, curr, paths=None, current_path=None):
    if paths is None:
        paths = []
    if current_path is None:
        current_path = []

    current_path.append(curr)
    if curr not in dic:
        paths.append(current_path)
    else:
        for succ in dic[curr]:
            getAllPath(dic, succ, paths, list(current_path))
    return paths

def getAllAPI(path):
    api = {}
    files =[]
    for dir,_,_ in os.walk(path+"/lancie-api/src/main/java/ch/wisv/areafiftylan/"):
        files.extend(glob.glob(os.path.join(dir,"*Controller.java")))
    for fname in files:
        f = open(fname, 'r')
        data = f.read()
        # print(fname)
        if(len(re.findall('@PreAuthorize.*[\n]+public class', data,re.MULTILINE))>0):
            for func in re.findall('(?! *public [a-zA-Z]+\(.*\) {)[public]? .* ([a-zA-Z]+)\(.*\) {', data):
                api[(fname[:-5].split("lancie-api/src/main/java/")[1].replace("/","."))+":"+func] = re.findall('@PreAuthorize\("(.*)"\)[\n]+public class', data,re.MULTILINE)
        else:
            for func in re.findall('(?! *public [a-zA-Z]+\(.*\) {)[public]? .* ([a-zA-Z]+)\(.*\) {', data):
                api[(fname[:-5].split("lancie-api/src/main/java/")[1].replace("/","."))+":"+func]  = re.findall('@PreAuthorize\("(.*)"\)\n(?: *@.*\n)* *.*'+func+"\(", data,re.MULTILINE)
    return api

def genPolicy(dic, events, api):
    policy = defaultdict(list)
    # print(getAllPath(dic,"ch.wisv.areafiftylan.users.controller.UserProfileRestController:addProfile"))
    for key, val in dic.items():
        func = (key.split()[0]+key.split()[2]).split("(")[0]
        if func in api:
            # print(key)
            # print(func)
            # paths = getAllPath(dic,key)
            for path in getAllPath(dic,key):
                isSensitive = False
                for f in path:
                    if func == "ch.wisv.areafiftylan.users.controller.UserProfileRestController:addProfile":
                        print(path)
                    funcname = (f.split()[0]+f.split()[2]).split("(")[0]
                    if funcname in events:
                        isSensitive = True
                        e = events[funcname]
                        break
                        # print(f)
                if isSensitive and not any([True for elem in policy[key] if e[0] == elem["Action"]]):
                    policy[key].append({"Principal": api[func], "Action":e[0], "Resource": e[1].capitalize()})
    return policy

if __name__ == "__main__":
    df = pd.read_csv("CallGraphEdge.csv", sep='\t', header=None).loc[:, [1, 3]]
    df.columns = ['caller', 'callee']
    df_both = df[(df.caller.str.contains("ch.wisv.areafiftylan") & df.callee.str.contains("ch.wisv.areafiftylan"))]
    parent2children,child2parents = buildGraph(df_both)
    # printTree(parent2children)
    events = getSensitiveEvents("output.txt")
    api = getAllAPI(".")
    policy = genPolicy(parent2children,events,api)
    with open('policy.json', 'w') as f:
        json.dump(policy, f, ensure_ascii=False, indent=4)
