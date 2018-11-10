var parser = new Vue({
  el: '#parser',
  data: {
    apiREST: 'http://localhost:3000',
    fwData: {
      host:{},            // Stores Host information: hostname, domain, Serial #, etc.
      users:[],           // Stores users defined in the config file.
      interfaces:[],      // Stores an array of interface objects with their properties.
      rules:{
        nat:[],         // List of NAT rules
        filter:[]       // List of Filter rules
      },
      routes:[],          // Stores route objects: {interface, destination, via, metric}
      notparsed:[],       // Stores lines that could not be understood
      objects:[],         // CISCO ASA: Network and Service Objects
      objectgroups:[]     // CISCO ASA: Object Groups
    },
    ajaxRequest: false,
    firewallParsed: false,
    parsed: false,
  },
  methods:{
    parseFirewall: function (event) {
      this.ajaxRequest = true;
      const options = {
        method: 'POST',
        headers: {'content-type':'application/json'},
        body: '{"cmd":"parseCfg", "cfgFile":"' + event.target.value + '", "workspace":true}'
      }
      fetch(this.apiREST + '/parse', options).then(res => res.json()).then(json => {
        this.ajaxRequest = false
        // console.log(options)
        console.log("response" + JSON.stringify(json))
        if ("error" in json) throw json.error
        workspacebar.createWorkspace(json.workspace.id,event.target.value)
      }).catch(error => {
        this.ajaxRequest = false
        console.error('POST request failed: ', error)
      })
    },
  },
})

Vue.component('workspace-menu',{
  template: `<li><a 
  v-bind:class="{active: isactive}"
  v-on:click="$emit('cevent-changews')">
  {{number}}</a></li>`,
  props: ['id', 'number', 'isactive']
})

var workspacebar = new Vue({
  el: '#workspacebar',
  data: {
    workspaces: [],
  },
  methods: {
    createWorkspace: function(ID,FILE){
      this.workspaces.push({id:ID, active:false, file:FILE, data:{}})
    },
    changeWorkspace: function(ID){
      this.workspaces.map(W => {
        if (W.active) W.active = false
        if (W.id == ID) W.active = true
      })
      mainworkspace.getHostData(ID)
    },
  },
})


var mainworkspace = new Vue({
  el: '#mainworkspace',
  data: {
    fwData: {
      host:{},            // Stores Host information: hostname, domain, Serial #, etc.
      users:[],           // Stores users defined in the config file.
      interfaces:[],      // Stores an array of interface objects with their properties.
      rules:{
        nat:[],         // List of NAT rules
        filter:[]       // List of Filter rules
      },
      routes:[],          // Stores route objects: {interface, destination, via, metric}
      notparsed:[],       // Stores lines that could not be understood
      objects:[],         // CISCO ASA: Network and Service Objects
      objectgroups:[]     // CISCO ASA: Object Groups
    },
    initialParse: true
  },
  methods: {
    getHostData: function(WSID) {
      fetch(parser.apiREST + '/' + WSID + '/hostdata').then(response => response.json()).then(json => {
        console.log(json)
        this.fwData.host = json.host
      })
    },
    getListItems: function(KEY) {
      fetch(this.apiREST + '/listitems?key=' + KEY)
      .then(response => response.json()).then(json => {
        this.fwData[KEY] = json.list
      })
    },
  }
})