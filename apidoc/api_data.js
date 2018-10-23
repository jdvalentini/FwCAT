define({ "api": [
  {
    "type": "get",
    "url": "/hostdata",
    "title": "Host information on the firewall (hostname, model, serial, etc.)",
    "version": "0.1.0",
    "name": "GetHostData",
    "group": "FwCAT",
    "success": {
      "fields": {
        "Success 200": [
          {
            "group": "Success 200",
            "type": "String",
            "optional": false,
            "field": "fwType",
            "description": "<p>Firewall parsing syntax.</p>"
          },
          {
            "group": "Success 200",
            "type": "String",
            "optional": false,
            "field": "serial",
            "description": "<p>Serial Number.</p>"
          },
          {
            "group": "Success 200",
            "type": "String",
            "optional": false,
            "field": "model",
            "description": "<p>Firewall model.</p>"
          },
          {
            "group": "Success 200",
            "type": "String",
            "optional": false,
            "field": "hostname",
            "description": "<p>Host Name.</p>"
          },
          {
            "group": "Success 200",
            "type": "String",
            "optional": false,
            "field": "domainname",
            "description": "<p>Firewall domain.</p>"
          }
        ]
      },
      "examples": [
        {
          "title": "Success-Response:",
          "content": "HTTP/1.1 200 OK\n{\n  \"fwType\": \"cisco-asa\",\n  \"model\": \"ASA5545\",\n  \"hostname\": \"ASATEST\"\n}",
          "type": "json"
        }
      ]
    },
    "error": {
      "fields": {
        "Error 5xx": [
          {
            "group": "Error 5xx",
            "optional": false,
            "field": "HostNotFound",
            "description": "<p>The host data is not present in the parsed results or the firewall has not been parsed</p>"
          }
        ]
      },
      "examples": [
        {
          "title": "Error-Response:",
          "content": "HTTP/1.1 500 Not Found\n{\n  \"error\": \"The parser was unable to retrieve host data\"\n}",
          "type": "json"
        }
      ]
    },
    "filename": "./api.js",
    "groupTitle": "FwCAT"
  }
] });
