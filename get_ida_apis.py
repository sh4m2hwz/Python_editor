#!/usr/bin/env python3

# Get all APIs from https://www.hex-rays.com/products/ida/support/idapython_docs
# Will dump idaapi.api, idc.api & idautils.api

import requests

from html.parser import HTMLParser
from html.entities import name2codepoint

hasFunc = False
hasArg = False
functions = dict()
curFunc = ""

class MyHTMLParser(HTMLParser):
    # https://docs.python.org/3/library/html.parser.html
    def handle_starttag(self, tag, attrs):
        global hasFunc, hasArg, functions, curFunc
        for attr in attrs:
            if attr[1] == "summary-sig-name":
                hasFunc = True
            if attr[1] == "summary-sig-arg":
                hasArg = True

    def handle_endtag(self, tag):
        global hasFunc, hasArg, functions, curFunc
        if hasFunc == True:
            hasFunc = False
        if hasArg == True:
            hasArg = False

    def handle_data(self, data):
        global hasFunc, hasArg, functions, curFunc
        if hasFunc == True:
            functions[data] = []
            curFunc = data
        if hasArg == True:
            functions[curFunc].append(data)

idaapi_urls=[
#"ida_allins", // no functions
"ida_auto",
"ida_bytes",
"ida_dbg",
"ida_diskio",
"ida_entry",
"ida_enum",
"ida_expr",
"ida_fixup",
"ida_fpro",
"ida_frame",
"ida_funcs",
"ida_gdl",
"ida_graph",
"ida_hexrays",
"ida_ida",
"ida_idaapi",
"ida_idc"
"ida_idd",
"ida_idp",
"ida_kernwin",
"ida_lines",
"ida_loader",
"ida_moves",
"ida_nalt",
"ida_name",
"ida_netnode",
"ida_offset",
"ida_pro",
"ida_problems",
"ida_range",
"ida_registry",
"ida_search",
"ida_segment",
"ida_segregs",
"ida_strlist",
"ida_struct",
"ida_typeinf",
"ida_tryblks",
"ida_ua",
"ida_xref",
]

def write_api(apis, fn):
    data = ""
    for api in sorted(apis):
        data += api + "\n"
    with open(fn, "w") as f:
        f.write(data)
    print(f"Done writing api to {fn}")

def get_api(urls, module):
    global hasFunc, hasArg, functions, curFunc
    hasFunc = False
    hasArg = False
    functions = dict()
    curFunc = ""
    apis = set()
    for u in urls:
        url = f"https://www.hex-rays.com/products/ida/support/idapython_docs/{u}-module.html"
        print(f"Getting API from {url}...")
        resp = requests.get(url)
        parser = MyHTMLParser()
        parser.feed(resp.text)
        for func_name, func_arg in functions.items():
            arg_str = ""
            for idx, arg in enumerate(func_arg):
                if idx == 0:
                    arg_str += f"{arg}"
                else:
                    arg_str += f", {arg}"
            apis.add(f"{module}.{func_name}({arg_str})")
    return apis

# get API for idaapi
idaapis = get_api(idaapi_urls, "idaapi")
write_api(idaapis, "idaapi.api")
# get API for idautils
urls = ["idautils"]
idautilsapis = get_api(urls, "idautils")
write_api(idautilsapis, "idautils.api")
# get api for idc
urls = ["idc"]
idcapis = get_api(urls, "idc")
write_api(idcapis, "idc.api")
