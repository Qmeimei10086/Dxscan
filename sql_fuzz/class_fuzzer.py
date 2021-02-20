import requests
import time
from sql_fuzz.my_utils import* 
from printf import*
from colorama import init,Fore,Back,Style
init(autoreset=True)

class Fuzzer():
        def __init__(self, url, headers={} ):
                self.url = url
                self.headers = headers
                self.count = 0
                
        def start_fuzz(self):
                printf("[sql_fuzz] [+] start fuzzing...","green")
                
                self.fuzz_sql()
                                
        def fuzz_sql( self, method='g', threshold=100, postdata={} ):
                base_url, query_list = analyze_url(self.url)
                sql_fuzz_vectors = load_vector('data/sql_fuzz.data')
                time_based_vectors = load_vector('data/sql_fuzz_time_based.data')
                sleep_time = 10
                for m in method:
                        if m == 'g':
                                weight_length = self.pre_weight_length(self.url)
                                q_len = len(query_list)
                                for i in range(q_len):
                                        query_string1 = "&".join(query_list[:i])+"&" if i != 0 else ""
                                        query_string2 = "&"+"&".join(query_list[i+1:]) if i+1 != q_len else ""
                                        for vector in sql_fuzz_vectors:
                                                query_string = "{0}{1}{2}{3}".format( query_string1, query_list[i], vector, query_string2 )
                                                final_url = "{0}?{1}".format(base_url, query_string)
                                                output = "[INFO]payload ==> "+final_url
                                                printf(output,"yellow")
                                                req = requests.get( final_url, headers=self.headers )
                                                
                                                r = self.check_sql_fuzz( req, weight_length, threshold ) 
                                                if r: 
                                                        output = "[sql_fuzz] [+]发现注入 " +"Payload => {0}".format( req.url )
                                                        postdate = {self.url:req.url}
                                                        requests.post('http://localhost:8848/sql', json=postdate)
                                                        printf(output,"green")
                                        if not self.count:
                                                for vector in time_based_vectors:
                                                        query_string = "{0}{1}{2}{3}".format( query_string1, query_list[i], vector.replace("*index*", str(sleep_time) ), query_string2 )
                                                        final_url = "{0}?{1}".format(base_url, query_string)
                                                        try:
                                                                req = requests.get( final_url, headers=self.headers, timeout=sleep_time-5 )
                                                        except Exception as e:
                                                                output = "[sql_fuzz] [+]发现注入 " +"Payload => {0}".format(final_url)
                                                                postdate = {self.url:final_url}
                                                                requests.post('http://localhost:8848/sql', json=postdate)
                                                                prinft(output,"green")
                        elif m == 'p':  
                                weight_length = self.pre_weight_length(self.url, method='p', postdata=postdata)  
                                
                                for k,v in postdata.items():
                                        for vector in sql_fuzz_vectors:
                                                temp = v
                                                postdata[k]+=vector
                                                req = requests.post(self.url, headers=self.headers, data=postdata )
                                                r = self.check_sql_fuzz( req, weight_length, threshold ) 
                                                if r: print("[*] Payload => {0} | URL => {1}".format( form_postdata(postdata),self.url ) )
                                                postdata[k] = temp
                                        if not self.count:
                                                for vector in time_based_vectors:
                                                        temp = v
                                                        try:
                                                                postdata[k]+=vector
                                                                req = requests.post( self.url, headers=self.headers, data=postdata, timeout=sleep_time-5 )
                                                        except Exception as e:
                                                                if r: print("[*] Payload => {0} | URL => {1}".format( form_postdata(postdata),self.url ) )
                                                        finally:
                                                                postdata[k] = temp
                
        def check_sql_fuzz(self, req, weight_length, threshold=100 ):
                content_length = len( req.text )
                if abs( content_length - weight_length ) <= threshold:
                        weight_length = ( content_length + weight_length ) // 2
                        r = False
                else:
                        self.count+=1
                        r = True
                return r
                
        def pre_weight_length(self, url, method='g', postdata={} ):
                if method == 'g':
                        req = requests.get( url, headers=self.headers )
                elif method == 'p':
                        req = requests.post( url, headers=self.headers, data=postdata )
                return len( req.text )
                
        def set_url(self, url):
                self.url = url
        def set_headers(self, headers):
                self.headers = headers
        def set_cookie(self, cookie):
                self.headers["Cookie"] = cookie
        def set_threshold(self, threshold):
                self.threshold = threshold
