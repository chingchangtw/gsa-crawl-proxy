This open source project provides an extensible mechanism to crawl content located in multiple secure sources with the same server instance. This tool acts as a proxy server that is in between the crawler (i.e. the Google Search Appliance) and the content sources, letting you fully customize the way the access to these sources is done at crawling time. This proxy is completely independent of the way the content is served.

It extends the crawling options natively implemented in the crawler, taking the advantage of the connectivity provided by the Authentication/Authorization modules for the GSA Valve Security Framework < http://code.google.com/p/gsa-valve-security-framework/ >. These modules implement the integration complexity to securely access to the content sources where documents are. The GSA Crawl Proxy is able to authenticate the crawler user coming from the search appliance using HTTP Basic, and send those credentials to any of these modules that can convert them to any security mechanism the content servers would understand.

Latest version: 1.0 (June 2008)