# -*- coding: utf-8 -*-
"""
Created on Wed Mar 21 03:35:20 2018

@author: Shomi Nanwani
"""

import requests
import re
import sys
from time import localtime, strftime
import check_internet
import time
import tkinter as tk
from tkinter import *
from PIL import ImageTk, Image

def current_time(expression):
	if expression=='date':
		tme=strftime("%d-%m", localtime())
	elif expression=='time':
		tme=strftime("%H:%M:%S", localtime())
	elif expression=='date-time':
		tme=strftime("%Y-%m-%d %H:%M:%S", localtime())
	return tme

def checkmd5(hash):

	# CHECKING HASH VALUE ON md5decrypt.net
	s = requests.Session()
	print(current_time("date-time")+" [i] Checking hash value on md5decrypt.net")
	data_payload={'87':'', 'decrypt':'Decrypt', 'hash':hash}
	response=s.post('https://md5decrypt.net/en/', data=data_payload, allow_redirects=True, timeout=30)
	op=re.compile(r'</div><br/>'+hash+' : <b>(.*?)</b><br/><br/>(.*?)<br/><br/>').findall(response.text)
	# print(response.text)
	if response.status_code!=200:
		print(current_time("date-time")+" [X] Unable to get response from md5decrypt.net, Response Code",response.status_code)
	elif "Found" not in response.text or op==[]:
		print(current_time("date-time")+" [X] Not found on md5decrypt.net")
	else:
		print(current_time("date-time")+" [+] Hash found:",op[0][0],"- ", op[0][1])
	s.cookies.clear()
	
	# CHECKING HASH VALUE ON hashtoolkit.com
	print(current_time("date-time")+" [i] Checking hash value on hashtoolkit.com")
	data_payload={'hash':hash}
	response=s.get('https://hashtoolkit.com/reverse-hash?hash='+hash, data=data_payload, allow_redirects=True, timeout=30)
	op=re.compile(r'title="decrypted md5 hash">(.*?)</span>').findall(response.text)
	if response.status_code!=200:
		print(current_time("date-time")+" [X] Unable to get response from hashtoolkit.com, Response Code",response.status_code)
	elif "No hashes found" in response.text or op==[]:
		print(current_time("date-time")+" [X] Not found on hashtoolkit.com")
	else:
		print(current_time("date-time")+" [+] Hash found:",op[0])
	s.cookies.clear()
	
	# CHECKING HASH VALUE ON hashkiller.co.uk
	s=requests.Session()
	print(current_time("date-time")+" [i] Checking hash value on hashkiller.co.uk")
	header_payload={
	'Host': 'hashkiller.co.uk',
	'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0',
	'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
	'Accept-Language': 'en-US,en;q=0.5',
	'Accept-Encoding': 'gzip, deflate',
	'DNT': '1',
	'Connection': 'close',
	'Upgrade-Insecure-Requests': '1'
	}
	response=s.get('https://hashkiller.co.uk/md5-decrypter.aspx', headers=header_payload, allow_redirects=True, timeout=30)
	eventargument=re.compile(r'id="__EVENTARGUMENT" value="(.*?)" />').findall(response.text)
	eventtarget=re.compile(r'id="__EVENTTARGET" value="(.*?)" />').findall(response.text)
	eventvalidation=re.compile(r'id="__EVENTVALIDATION" value="(.*?)" />').findall(response.text)
	viewstate=re.compile(r'id="__VIEWSTATE" value="(.*?)" />').findall(response.text)
	viewstategenerator=re.compile(r'id="__VIEWSTATEGENERATOR" value="(.*?)" />').findall(response.text)
	value1=re.compile(r'<span id="content1_lblStatus">&nbsp;</span>\n<input type="hidden" name="(.*?)" id=".*?" value="(.*?)" />').findall(response.text)
	captcha=re.compile(r'<img id="content1_imgCaptcha" src="(.*?)" alt="Captcha"').findall(response.text)
	print(current_time("date-time")+" [i] Getting CAPTCHA")

	header_payload={
		'Host': 'hashkiller.co.uk',
		'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0',
		'Accept': '*/*',
		'Accept-Language': 'en-US,en;q=0.5',
		'Accept-Encoding': 'gzip, deflate',
		'Referer': 'https://hashkiller.co.uk/md5-decrypter.aspx',
		'DNT': '1',
		'Connection': 'close'
	}
	file=s.get('https://hashkiller.co.uk'+captcha[0], headers=header_payload, allow_redirects=True, timeout=30)
	with open("captcha.jpeg", 'wb') as f:
				f.write(file.content)
				print(current_time("date-time")+" [i] Captcha Downloaded.")

	window = tk.Tk()
	window.title("Captcha")
	path = "captcha.jpeg"
	img = ImageTk.PhotoImage(Image.open(path))
	panel = tk.Label(window, image= img)
	panel.pack(side="top")
	def evaluate(event):
		global captcha_text
		res.configure(text = "Enter CAPTCHA text: " + entry.get())
		captcha_text=entry.get()
		window.quit()
	Label(window, text="Enter Captcha: ").pack()
	entry = Entry(window)
	entry.bind("<Return>", evaluate)
	entry.pack()
	res = Label(window)
	res.pack()
	mainloop()

	payload = {
		'__EVENTARGUMENT':'',
		'__EVENTTARGET':'',
		'__EVENTVALIDATION':eventvalidation[0],
		'__VIEWSTATE':viewstate[0],
		'__VIEWSTATEGENERATOR':viewstategenerator[0],
		value1[0][0]:value1[0][1],
		'ctl00$content1$btnSubmit':'Submit',
		'ctl00$content1$txtCaptcha':captcha_text,
		'ctl00$content1$txtInput':hash
		}
	header_payload={
		'Host': 'hashkiller.co.uk',
		'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0',
		'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
		'Accept-Language': 'en-US,en;q=0.5',
		'Accept-Encoding': 'gzip, deflate',
		'Referer': 'https://hashkiller.co.uk/md5-decrypter.aspx',
		'Content-Type': 'application/x-www-form-urlencoded',
		'Content-Length': '',
		'DNT': '1',
		'Connection': 'close',
		'Upgrade-Insecure-Requests': '1'
	}
	response=s.post('https://hashkiller.co.uk/md5-decrypter.aspx', data=payload, headers=header_payload, allow_redirects=True, timeout=30)
	if 'Failed to find any hashes!' in response.text:
		print(current_time("date-time")+" [X] Not found on hashkiller.co.uk")
	else:
		op=re.compile(r'<span id="content1_lblResults" class="results">'+hash+' MD5 : <span class="text-green">(.*?)</span><br />').findall(response.text)
		print(current_time("date-time")+" [+] Hash found:",op[0])
	
if len (sys.argv) != 2 :
    print("Usage: python md5decrypt.py <hash>")
    sys.exit (1)

hash=sys.argv[1]
print(current_time("date-time")+" Hash:",hash)

if check_internet.is_connected() is True:
	print(current_time("date-time")+" [*] Connected to Internet")
	checkmd5(hash)
		