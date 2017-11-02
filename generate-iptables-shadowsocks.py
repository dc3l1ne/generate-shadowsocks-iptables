import urllib2
import re
import argparse
class Main:
	def run(self):
		parser=argparse.ArgumentParser(description="Generate routing rules for vpn.")
		parser.add_argument('-o','--output',
						dest='output',
						default='ss-iptables',
						nargs='?',
						help="The name of output file" )
		parser.add_argument('-p','--port',
						dest='port',
						default='5555',
						nargs='?',
						help="The port of ss-redir" )				
		args = parser.parse_args()
		if args.output:
			try:
				self.port=int(args.port)
				self.oname=args.output.lower()
				self.fetch_ip_data()
				self.to_file()
			except:
				print 'Please input a correct port'
				exit()
	def fetch_ip_data(self): 
	#This part is from "chnroute project" https://github.com/fivesheep/chnroutes
		#fetch data from apnic
		print "Fetching data from apnic.net, it might take a few minutes, please wait..."
		url=r'http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest'
		data=urllib2.urlopen(url).read()
		cnregex=re.compile(r'apnic\|cn\|ipv4\|[0-9\.]+\|[0-9]+\|[0-9]+\|a.*',re.IGNORECASE)
		cndata=cnregex.findall(data)
		self.results=[]
		for item in cndata:
			unit_items=item.split('|')
			starting_ip=unit_items[3]
			num_ip=int(unit_items[4])
			imask=0xffffffff^(num_ip-1)
			cidr=str(((bin(int(imask)))).count('1')) #Convert to CIDR
			self.results.append('%s/%s'%(starting_ip,cidr))
	def to_file(self):
		print 'Writing to %s\n'%self.oname
		f=open(self.oname,'a')
		f.write('iptables -t nat -N SHADOWSOCKS\n')
		f.write('iptables -t nat -A SHADOWSOCKS -d 0.0.0.0/8 -j RETURN\n')
		f.write('iptables -t nat -A SHADOWSOCKS -d 10.0.0.0/8 -j RETURN\n')
		f.write('iptables -t nat -A SHADOWSOCKS -d 127.0.0.0/8 -j RETURN\n')
		f.write('iptables -t nat -A SHADOWSOCKS -d 169.254.0.0/16 -j RETURN\n')
		f.write('iptables -t nat -A SHADOWSOCKS -d 172.16.0.0/12 -j RETURN\n')
		f.write('iptables -t nat -A SHADOWSOCKS -d 192.168.0.0/16 -j RETURN\n')
		f.write('iptables -t nat -A SHADOWSOCKS -d 224.0.0.0/4 -j RETURN\n')
		f.write('iptables -t nat -A SHADOWSOCKS -d 240.0.0.0/4 -j RETURN\n')
		f.write("iptables -t nat -A SHADOWSOCKS -d ss'server -j RETURN\n")
		for data in self.results:
			f.write('iptables -t nat -A SHADOWSOCKS -d %s -j RETURN\n'%data)
		f.write('iptables -t nat -A SHADOWSOCKS -p tcp -j REDIRECT --to-ports %d\n'%self.port)
		f.write('iptables -t nat -A PREROUTING -p tcp -j SHADOWSOCKS')
		f.close()
		print 'All Done!'
if __name__=='__main__':
	run=Main()
	run.run()
