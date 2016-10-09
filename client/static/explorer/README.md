#Hyperledger Explorer
This is the initial release of the Hyperledger explorer which provides a User Interface to explore and examine the current state of the Hyperledger blockchain in a convenient and easy to use manner. Similar to bitcoin explorers or crypto-currency explorers, information such as transaction information, network activity, recent blocks, visuals and search etc. are available that allows for information to be quickly found.

The explorer relies on the current gRPC rest APIs that are available. To run the explorer make sure that at least one validating peer is running.
>  cd $GOPATH/github.com/hyperledger/fabric/peer 

> peer node start 

After a validating peer is running, start up a http server to handle the REST APIs 

>  cd $GOPATH/github.com/hyperledger/fabric/core/rest 

> http-server -a 0.0.0.0 -p 5554 --cors 

You should now be able to open up index.html in the browser of your choice and have access to the explorer. In scripts.js, the REST_ENDPOINT is defined which makes the http requests to the gRPC APIs that are available. By default it is set to:

> const REST_ENDPOINT = 'http://127.0.0.1:5000' 

You can modify this at any time depending on you http server specifications

Video Demonstration:
https://vimeo.com/174814785

