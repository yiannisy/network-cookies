# Network Cookies

This repo contains python and JS libraries for network cookies, along with sample utilities for testing.

Background information on network cookies is available on this paper : [Neutral Net Neutrality](http://yuba.stanford.edu/~yiannis/neutral-net-neutrality.pdf)

Check [AnyLink](http://anylink.stanford.edu) if you want to try network cookies from your browser.

To use it just add lib to your PYTHONPATH and "import cookies"

    ├── README
    ├── lib # basic python and Javascript libraries to generate and match against cookies.
    │   ├── cookie.js 
    │   └── cookies.py 
    └── utils
        ├── cookie_wget.py # wrapper for wget to introduce cookies (usage: ./cookie_wget.py http://www.stanford.edu)
        └── http_client.py # simple http client that uses cookies (usage: ./http_client.py http://www.stanford.edu)
