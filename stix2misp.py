from os.path import isfile, isdir, join
from os import listdir
import json
from stix2 import MemoryStore, Indicator, Bundle, parse
import pathlib
import pyaml
import logging
import sys
import pymisp
from uuid import uuid4
import datetime
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def display_banner():
    print("STIX to MISP Mapping Document: https://github.com/MISP/misp-stix/tree/main/documentation")
    print("PyMISP Tutorial: https://github.com/MISP/PyMISP/blob/main/docs/tutorial/FullOverview.ipynb")
    print("stix2 Example: https://oasis-open.github.io/cti-documentation/examples/identifying-a-threat-actor-profile")
    print("logs module: https://docs.python.org/zh-tw/3/howto/logging.html")
    print("------------------------------------------")


# 取得當下路徑
absolute_url = pathlib.Path(__file__).parent.absolute()
logging.basicConfig(filename=str(absolute_url)+'/logs/' +
                    str(datetime.datetime.now())+".log", encoding='utf-8', level=logging.INFO)
log = logging.getLogger(__name__)
log.setLevel(logging.ERROR)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.ERROR)
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
log.addHandler(ch)


def get_stix_file():
    # 指定要列出所有檔案的目錄
    mypath = str(absolute_url)+"/ImportFile"
    # 取得所有檔案與子目錄名稱
    files = listdir(mypath)
    stix_files = []
    # 以迴圈處理
    for f in files:
        # 產生檔案的絕對路徑
        fullpath = join(mypath, f)
        # 判斷 fullpath 是檔案還是目錄
        if isfile(fullpath):
            log.info("檔案讀取: %s", f)
            stix_files.append(mypath+"/"+f)
    return stix_files


def get_config(configfile):
    try:
        absolute_url = pathlib.Path(__file__).parent.absolute()
        with open(str(absolute_url)+"/"+configfile, "r") as f:
            CONFIG = pyaml.yaml.load(f)
            return CONFIG
    except FileNotFoundError:
        log.fatal("Could not find config file %s", configfile)
        print("exit")


def get_bundle(file):
    testfile = file
    with open(testfile) as stix2_json_file:
        stix2_dict_file = json.load(stix2_json_file)
        indicators_dict = {}
        indicators_list = []
        for stix2_dict_objects_file in stix2_dict_file["objects"]:
            indicator = parse(json.dumps(stix2_dict_objects_file))
            # print(type(indicator))
            indicators_dict.update({stix2_dict_objects_file["id"]: indicator})
            indicators_list.append(indicator)
            # indicator.serialize(pretty=True)
        bundle = Bundle(objects=indicators_list)
        # for obj in bundle.objects:
        #     print(obj)
        return bundle


def create_object_sectoolstw(object_name):
    absolute_url = pathlib.Path(__file__).parent.absolute()
    object = pymisp.MISPObject(
        name=object_name, strict=True, misp_objects_path_custom=str(absolute_url)+'/sectoolstw-objects')
    return object


def create_object_misp(object_name):
    absolute_url = pathlib.Path(__file__).parent.absolute()
    object = pymisp.MISPObject(
        name=object_name, strict=True, misp_objects_path_custom=str(absolute_url)+'/objects')
    return object


def insert_attribute_in_object(misp_object, obj):
    for key in obj:
        if key != "type" and key != "revoked" and key != "defanged":
            try:
                misp_object.add_attribute(
                    key, value=obj[key])  # 將屬性 加到 自訂 object
            except Exception as e:
                log.warning(e)
    return misp_object


def stix_to_misp(bundle):
    event = pymisp.MISPEvent()
    event.distribution = 0
    event.threat_level_id = 2
    event.analysis = 0
    for obj in bundle.objects:
        if obj["type"] == "report":
            event.info = obj["name"] + " - " + obj["description"]
            event.set_date(obj["published"])
        elif obj["type"] == "grouping":
            event.info = obj["name"] + " - " + obj["description"]
        elif obj["type"] == "marking-definition":
            event.add_tag(obj["name"])
        else:
            try:
                misp_object = create_object_sectoolstw(
                    obj["type"])  # 建立自訂 object
                insert_attribute_in_object(misp_object, obj)
                event.add_object(misp_object)  # 將物件添加到 event 上
            except:
                log.warning(
                    "Could not find MISP-Object in sectoolstw-objects: %s", obj["type"])
                try:
                    misp_object = create_object_misp(
                        obj["type"])  # 建立自訂 object
                    insert_attribute_in_object(misp_object, obj)
                    event.add_object(misp_object)  # 將物件添加到 event 上
                except:
                    log.fatal(
                        "Could not find MISP-Object in objects: %s in %s", obj["type"], bundle.id)
    try:
        event = misp.add_event(event, pythonify=True)
        print("Upload Success!")
    except Exception as e:
        print("event upload fail - %s", e)


display_banner()                        # 顯示工具 Title

CONFIG = get_config("misp_config.yml")     # MISP 登入配置檔
misp = pymisp.ExpandedPyMISP(
    CONFIG["MISP"]["URL"], CONFIG["MISP"]["KEY"], CONFIG["MISP"]["VERIFYCERT"])  # 建立 MISP 連線

stix_files = get_stix_file()
for file in stix_files:
    bundle = get_bundle(file)                   # 抓取 STIX2.1 的檔案
    stix_to_misp(bundle)
