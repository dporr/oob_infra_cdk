import CloudFlare
import json, os

def handler():
    cf = CloudFlare.CloudFlare(key=os.getenv("CF_API"))
    cf.zones.
    print(dir())

handler()