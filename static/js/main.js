// import Vue from 'vue'
// import VueResource from 'vue-resource'
// Vue.use(VueResource)
// Vue.http.options.emulateJSON = true
// const http=Vue.http
// export default http
// Vue.use(require('vue-resource'))

var main = new Vue({
  el: '#main',
  data: {
    rules: [
      {linenumber:1, srcInterface:"ETH0", dstInterface:"ETH1"},
      {linenumber:2, srcInterface:"ETH2", dstInterface:"ETH1"},
      {linenumber:4, srcInterface:"ETH2", dstInterface:"ETH0"},
    ],
    firewallParsed: false,
    apiREST: 'http://localhost:3000',
    ajaxRequest: false,
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
    parsed: false,
  },
  methods:{
    parseFirewall: function (event) {
      this.ajaxRequest = true;
      // console.log(event.target.value)
      const options = {
        method: 'POST',
        headers: {'content-type':'application/json'},
        body: '{"cmd":"parseCfg", "cfgFile":"' + event.target.value + '"}'
      }
      fetch(this.apiREST + '/parse', options).then(data => {
        this.ajaxRequest = false
        console.log(data)
        // this.fwHostData = this.getHostData()
        this.parsed = true
      }).catch(error => {
        console.error('POST request failed: ', error)
      })
      
      // this.firewallParsed = true
    },
    getHostData: function() {
      fetch(this.apiREST + '/hostdata').then(response => response.json()).then(json => {
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
  },
  // created(){
  //   fetch(this.apiREST).then(response => response.json).then(json => {
  //     this.rules = json.items
  //   })
  // ,}
})

/* <ul>
{% for key,props in menu.items %}
        <li>{% if active == key %}<a class="active" href={{props.url}}>
            {% else %} <a href={{props.url}}>
            {% endif %}
                {{ key }}
        </a></li>
{% endfor %}
</ul> */

// Vue.component('workspace-menu',{
//   template: '<li><a v-on:click="changeWorkspace(id)">{{cont}}</a></li>',
//   props: ['id', 'cont']
// })

// Vue.component('fw-filter-rules',{
//   template: '\
//   <div class="col"></div>\
//   ',
// })


// Vue.component('todo-item', {
//     template: '\
//       <li>\
//         {{ title }}\
//         <button v-on:click="$emit(\'remove\')">Remove</button>\
//       </li>\
//     ',
//     props: ['title']
//   })
  
//   new Vue({
//     el: '#todo-list-example',
//     data: {
//       newTodoText: '',
//       todos: [
//         {
//           id: 1,
//           title: 'Do the dishes',
//         },
//         {
//           id: 2,
//           title: 'Take out the trash',
//         },
//         {
//           id: 3,
//           title: 'Mow the lawn'
//         }
//       ],
//       nextTodoId: 4
//     },
//     methods: {
//       addNewTodo: function () {
//         this.todos.push({
//           id: this.nextTodoId++,
//           title: this.newTodoText
//         })
//         this.newTodoText = ''
//       }
//     }
//   })

// var comp = new Vue({
//     el: '#comp',
//     data: {
//         grocery: [
//             {id:0, text: 'Veggies'},
//             {id:1, text: 'Meat'},
//             {id:2, text: 'Milk'},
//         ],
//     },
//     created: function (){
//         console.log('Grocery is: ' + JSON.stringify(this.grocery))
//     },
// })