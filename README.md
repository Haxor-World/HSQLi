# HSQLi
<p align="center">
<h2 align="center">HSQLi</h2>
<h4 align="center">Human SQL Injection Finder</h4>
<img src="https://i.top4top.io/p_2687ni1n71.png" align="center" alt="GitHub Readme Stats" />

<font align="center">HSQLi is used to discover SQL Injection using Dorks. it's also counting of coloums of Union-Based Method</font>

> Requirements modules
+ argparse
+ requests
+ beautifulsoup4 

> Arguments function
+ --limit -> to limits of urls that has been dorked

> Demo run
<img src="https://g.top4top.io/p_2687w8yrl1.png" align="center" alt="GitHub Readme Stats" />

> how to run
```
main.py allinurl=index.php?id= > no limit 
main.py allinurl=index.php?id= --limit 12 > to limit just 12 urls to scan
```
> support multiply scan
```
main.py "inlink:index.php?id=" "inlink:gallery.php?id="
```
