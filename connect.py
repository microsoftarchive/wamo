#!/usr/bin/python

import OpenSSL.crypto
import azure.servicemanagement
import base64
import os
import sys
import tempfile
import xml.dom.minidom

def print_stuff(obj):
    for item in dir(obj):
        if str(item)[:2] != '__':
            print "%s : %s" % (item, getattr(obj, item))

def pkcs12_to_pem(pkcs12_buffer):
    pkcs12 = OpenSSL.crypto.load_pkcs12(pkcs12_buffer)
    cert = pkcs12.get_certificate()
    private_key = pkcs12.get_privatekey()
    cert_pem = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    pkey_pem = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, private_key)
    (pem_fd, pem_path) = tempfile.mkstemp()
    pem_file = os.fdopen(pem_fd, "w")
    pem_file.write(pkey_pem)
    pem_file.write(cert_pem)
    pem_file.close
    return pem_path

def publishsettings_handler(ps):
    ps_doc = xml.dom.minidom.parse(ps)
    publish_data = ps_doc.getElementsByTagName("PublishData")[0]
    publish_profile = publish_data.getElementsByTagName("PublishProfile")[0]
    pkcs12_b64 = publish_profile.getAttribute("ManagementCertificate")
    sub = publish_profile.getElementsByTagName("Subscription")[0]
    sub_id = sub.getAttribute("Id")
    pkcs12_buf = base64.b64decode(pkcs12_b64)
    return (sub_id, pkcs12_buf)

publishsettings = sys.argv[1]
(sub_id, pkcs12_buf) = publishsettings_handler(publishsettings)
pem_path = pkcs12_to_pem(pkcs12_buf)


service = azure.servicemanagement.ServiceManagementService(subscription_id=sub_id, cert_file=pem_path)

accounts =  service.list_storage_accounts()
print "-------List storage accounts"
for account in accounts:
    print "-------Account info"
    print_stuff(account)
    print "-------Account properties"
    print_stuff(account.storage_service_properties)


account = service.get_storage_account_properties(accounts[0].service_name)
print "-------Get storage account properties"
print "-------Account info"
print_stuff(account)
print "-------Account properties"
print_stuff(account.storage_service_properties)

account = service.get_storage_account_keys(accounts[0].service_name)
print "-------Get storage account keys"
print "-------Account info"
print_stuff(account)
print "-------Account keys"
print_stuff(account.storage_service_keys)

hosted = service.list_hosted_services()
print "-------List hosted services"
for svc in hosted:
    print "-------Hosted Service"
    print_stuff(svc)
    print "-------Hosted Service Properties"
    print_stuff(svc.hosted_service_properties)

svc = service.get_hosted_service_properties(hosted[0].service_name, embed_detail=True)
print "-------Get hosted service properties"
print "-------Hosted Service"
print_stuff(svc)
print "-------Hosted Service Properties"
print_stuff(svc.hosted_service_properties)
print "-------Hosted Service Deployments"
for deployment in svc.deployments:
    print "-------Deployment"
    print_stuff(deployment)
    for role_inst in deployment.role_instance_list:
        print "-------Role Instance"
        print_stuff(role_inst)
    for role in deployment.role_list:
        print "-------Role"
        print_stuff(role)

deployment = service.get_deployment_by_slot(svc.service_name, "Production")
print "-------Get Deployment"
print_stuff(deployment)
for role_inst in deployment.role_instance_list:
    print "-------Role Instance"
    print_stuff(role_inst)
for role in deployment.role_list:
    print "-------Role"
    print_stuff(role)

aff_grps = service.list_affinity_groups()
print "-------List Affinity Groups"
for grp in aff_grps:
    print "-------Affinity Group"
    print_stuff(grp)

#aff_grp_prop = service.get_affinity_group_properties(aff_grps[0].name)
#print "-------Affinity Group Properties"
#print_stuff(aff_grp_prop)
#print "-------Affinity Group Hosted Services"
#print_stuff(aff_grp_prop.hosted_services)
#print "-------Affinity Group Storage Services"
#print_stuff(aff_grp_prop.storage_services)

#locations = service.list_locations()
#print "-------Locations"
#for location in locations:
#    print_stuff(location)

#oses = service.list_operating_systems()
#print "-------OSes"
#for o_s in oses:
#    print_stuff(o_s)

#os_fams = service.list_operating_system_families()
#print "-------OS Families"
#for fam in os_fams:
#    print_stuff(fam)

sub = service.get_subscription()
print "-------Subscription"
print_stuff(sub)

role = service.get_role(svc.service_name, deployment.name, deployment.role_list[0].role_name)
print "-------Role"
print_stuff(role)
for conf_set in role.configuration_sets:
    print "-------Role Config Set"
    print_stuff(conf_set)
    for inp_ep in conf_set.input_endpoints:
        print "-------Role Config Set Input Endpoint"
        print_stuff(inp_ep)
for data_disk in role.data_virtual_hard_disks:
    print "-------Role Data Disk"
    print_stuff(data_disk)
print "-------Role OS Disk"
print_stuff(role.os_virtual_hard_disk)

#images = service.list_os_images()
#print "-------List OS Images"
#for image in images:
#    print "-------Image"
#    print_stuff(image)



os.unlink(pem_path)
