#
# it's not pretty; probably a better way; little data drops out; acceptable losses.
#

printsuccess=0
printfail=1

import sys

def main(argv):

    import re

#Fields: date time time-taken c-ip cs-username cs-auth-group x-exception-id sc-filter-result cs-categories cs(Referer) sc-status s-action cs-method rs(Content-Type) cs-uri-scheme cs-host cs-uri-port cs-uri-path cs-uri-query cs-uri-extension cs(User-Agent) s-ip sc-bytes cs-bytes x-virus-id

    #level 1 match - matches most
    fullmatch = re.compile(r'' +
        '^(?P<datetime>\d+-\d+-\d+ \d+:\d+:\d+)\s+(?P<anumber>\d+)\s+(?P<host>[\da-f\.]+)\s+(?P<adash1>[^ ]+)\s+(?P<adash2>[^ ]+)\s+(?P<adash3>[^ ]+)\s+(?P<filter_result>[^ ]+)\s+\"(?P<filter_result_thing>[^\"]+)\"\s+(?P<full_uri>[^ ]+)\s+(?P<http_response_code>\d+)\s+(?P<connection_result>[^ ]+)\s+(?P<request_method>[^ ]+)\s+(?P<response_mime_type>[^ ]+)\s+(?P<protocol>[^ ]+)\s+(?P<request_host>[^ ]+)\s+(?P<dst_port>\d+)\s+(?P<request_uri>[^ ]+)\s+(?P<request_params>[^ ]+)\s+(?P<file_extension>[^ ]+)\s+(\"(?P<user_agent>[^\"]+)\"|\-)\s+(?P<an_ip_address>[\d\.]+)\s+(?P<bytes_in>\d+)\s+(?P<bytes_out>\d+)\s+(?P<somelastthing>[^ ]+)$'
        )

    #open file for output stream
    # Open a file
    fo = open("outputSG.csv", "w")
    print "Name of the file: ", fo.name
    print "Closed or not : ", fo.closed
    print "Opening mode : ", fo.mode
    print "Softspace flag : ", fo.softspace

    #write the header
    fo.write("datetime,anumber,host,adash1,adash2,adash3,filter_result,filter_result_thing,full_uri,http_response_code,connection_result,request_method,response_mime_type,protocol,request_host,request_uri,dst_port,request_params,file_extension,user_agent,an_ip_address,bytes_in,bytes_out,somelastthing\n")

    import glob

    filecount=0
    totalsucccount=0
    totalfailcount=0
    totalskipcount=0

    for f in glob.glob('./bluesmote/*.log'):

        with open(f,"r") as fp:
            filecount+=1
            fullproccount=0
            failcount=0
            skipcount=0

            for line in fp:
                status="failed"

                iplist = fullmatch.search(line)

                if iplist:
                    fullproccount+=1
                    status="fullmatch"

                    if printsuccess:
                        print line
                        print iplist.groups()
                        print iplist.groupdict()

                    # datetime
                    if iplist.groupdict().has_key("datetime"):
                    	datetime = iplist.group("datetime")
                    else:
                    	datetime = "-"
                    if printsuccess:
                        print "datetime:",datetime


                    # anumber
                    if iplist.groupdict().has_key("anumber"):
                    	anumber = iplist.group("anumber")
                    else:
                    	anumber = "-"
                    if printsuccess:
                        print "anumber:",anumber


                    # hashthing - proxy host
                    if iplist.groupdict().has_key("host"):
                    	host = iplist.group("host")
                    else:
                    	host = "-"
                    if printsuccess:
                        print "host:",host


                    # adash1
                    if iplist.groupdict().has_key("adash1"):
                    	adash1 = iplist.group("adash1")
                    else:
                    	adash1 = "-"
                    if printsuccess:
                        print "adash1:",adash1


                    # adash2
                    if iplist.groupdict().has_key("adash2"):
                    	adash2 = iplist.group("adash2")
                    else:
                    	adash2 = "-"
                    if printsuccess:
                        print "adash2:",adash2


                    # adash3
                    if iplist.groupdict().has_key("adash3"):
                    	adash3 = iplist.group("adash3")
                    else:
                    	adash3 = "-"
                    if printsuccess:
                        print "adash3:",adash3


                    # filter_result
                    if iplist.groupdict().has_key("filter_result"):
                    	filter_result = iplist.group("filter_result")
                    else:
                    	filter_result = "-"
                    if printsuccess:
                        print "filter_result:",filter_result


                    # filter_result_thing
                    if iplist.groupdict().has_key("filter_result_thing"):
                    	filter_result_thing = iplist.group("filter_result_thing")
                    else:
                    	filter_result_thing = "-"
                    if printsuccess:
                        print "filter_result_thing:",filter_result_thing


                    # full_uri
                    if iplist.groupdict().has_key("full_uri"):
                    	full_uri = iplist.group("full_uri")
                    else:
                    	full_uri = "-"
                    if printsuccess:
                        print "full_uri:",full_uri


                    # http_response_code
                    if iplist.groupdict().has_key("http_response_code"):
                    	http_response_code = iplist.group("http_response_code")
                    else:
                    	http_response_code = "-"
                    if printsuccess:
                        print "http_response_code:",http_response_code


                    # connection_result
                    if iplist.groupdict().has_key("connection_result"):
                    	connection_result = iplist.group("connection_result")
                    else:
                    	connection_result = "-"
                    if printsuccess:
                        print "connection_result:",connection_result


                    # request_method
                    if iplist.groupdict().has_key("request_method"):
                    	request_method = iplist.group("request_method")
                    else:
                    	request_method = "-"
                    if printsuccess:
                        print "request_method:",request_method


                    # response_mime_type
                    if iplist.groupdict().has_key("response_mime_type"):
                    	response_mime_type = iplist.group("response_mime_type")
                    else:
                    	response_mime_type = "-"
                    if printsuccess:
                        print "response_mime_type:",response_mime_type


                    # protocol
                    if iplist.groupdict().has_key("protocol"):
                    	protocol = iplist.group("protocol")
                    else:
                    	protocol = "-"
                    if printsuccess:
                        print "protocol:",protocol


                    # request_host
                    if iplist.groupdict().has_key("request_host"):
                    	request_host = iplist.group("request_host")
                    else:
                    	request_host = "-"
                    if printsuccess:
                        print "request_host:",request_host




                    # dst_port
                    if iplist.groupdict().has_key("dst_port"):
                    	dst_port = iplist.group("dst_port")
                    else:
                    	dst_port = "-"
                    if printsuccess:
                        print "dst_port:",dst_port


                    # request_uri
                    if iplist.groupdict().has_key("request_uri"):
                    	request_uri = iplist.group("request_uri")
                    else:
                    	request_uri = "-"
                    if printsuccess:
                        print "request_uri:",request_uri


                    # request_params
                    if iplist.groupdict().has_key("request_params"):
                    	request_params = iplist.group("request_params")
                    else:
                    	request_params = "-"
                    if printsuccess:
                        print "request_params:",request_params


                    # file_extension
                    if iplist.groupdict().has_key("file_extension"):
                    	file_extension = iplist.group("file_extension")
                        # if(len(file_extension)>7):
                        #     print "file_extension 7 len error:",file_extension
                        #     print line
                    else:
                    	file_extension = "-"
                    if printsuccess:
                        print "file_extension:",file_extension


                    # user_agent
                    if iplist.groupdict().has_key("user_agent"):
                    	user_agent = iplist.group("user_agent")
                        if(user_agent is None):
                                user_agent = "-"
                    else:
                    	user_agent = "-"
                    if printsuccess:
                        print "user_agent:",user_agent


                    # an_ip_address
                    if iplist.groupdict().has_key("an_ip_address"):
                    	an_ip_address = iplist.group("an_ip_address")
                    else:
                    	an_ip_address = "-"
                    if printsuccess:
                        print "an_ip_address:",an_ip_address


                    # bytes_in
                    if iplist.groupdict().has_key("bytes_in"):
                    	bytes_in = iplist.group("bytes_in")
                    else:
                    	bytes_in = "-"
                    if printsuccess:
                        print "bytes_in:",bytes_in


                    # bytes_out
                    if iplist.groupdict().has_key("bytes_out"):
                    	bytes_out = iplist.group("bytes_out")
                    else:
                    	bytes_out = "-"
                    if printsuccess:
                        print "bytes_out:",bytes_out


                    # somelastthing
                    if iplist.groupdict().has_key("somelastthing"):
                    	somelastthing = iplist.group("somelastthing")
                    else:
                    	somelastthing = "-"
                    somelastthing=somelastthing.strip()
                    if printsuccess:
                        print "somelastthing:",somelastthing


                    eventstate="success"

                    if printsuccess:
                        print "--------------------BEGIN--------------------"

                        print line

                    outstring='","'.join((datetime,anumber,host,adash1,adash2,adash3,filter_result,filter_result_thing,full_uri,http_response_code,connection_result,request_method,response_mime_type,protocol,request_host,request_uri,dst_port,request_params,file_extension,user_agent,an_ip_address,bytes_in,bytes_out,somelastthing))
                    outstring='"'+outstring+'"'
                    outstring+="\n"
                    if printsuccess:
                        print outstring
                    fo.write(outstring)

                else:
                    failcount+=1

                    if printfail:
                        print ":::ERROR::: no full match found for event:",f
                        print line

                if printsuccess:
                    print "-------------------- END --------------------",status,"\n"

        fo.flush()

        #print "file",f,"success:",fullproccount,"failed:",failcount
        totalsucccount+=fullproccount
        totalfailcount+=failcount
        totalskipcount+=skipcount

    print "totalfiles",filecount,"success:",totalsucccount,"failed:",totalfailcount,"skipped:",totalskipcount

    fo.close()

if __name__ == "__main__":
    sys.exit(main(sys.argv))
