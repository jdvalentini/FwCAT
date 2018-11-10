// This file is required by the index.html file and will
// be executed in the renderer process for that window.
// All of the Node.js APIs are available in this process.
const ipc = require('electron').ipcRenderer
// const vue = require('vue')

ipc.on('firewallParsed',(event,data) => {
    console.log('Parsed '+ data.cfgFile)
    workspacebar.createWorkspace(data.cfgFile, data.fwConfig)
})

Vue.component('workspace-menu',{
    template: `<li><a 
        v-bind:class="{active: isactive}"
        v-on:click="$emit('cevent-changews')">
        {{number}}</a></li>`,
    props: ['id', 'number', 'isactive']
})

window.culo = "caca"

window.parser = new Vue({
    el: '#parser',
    data: {
        apiREST: 'http://localhost:3000',
        ajaxRequest: false,
    },
    methods:{
        parseFirewall: function (event) {
            console.log(event.target.value)
            ipc.send('parseFirewall',{configFile: event.target.value})
        },
    },
})
  
window.workspacebar = new Vue({
    el: '#workspacebar',
    data: {
        workspaces: [],
    },
    methods: {
        createWorkspace: function(FILE,CONFIG){
            while (true){
                var rnd = [...Array(15)].map(i=>(~~(Math.random()*36)).toString(36)).join('')
                if (this.workspaces.filter(o => o.id == rnd).length == 0) break
            }
            this.workspaces.push({id:rnd, active:false, file:FILE, data:CONFIG})
            return WORKSPACES
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
  
  
window.mainworkspace = new Vue({
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
        initialParse: true,
    },
    methods: {
        getHostData: function() {
            this.fwData.host = json.host
        },
    }
})