import React, { Component } from 'react';
import ReactTable from 'react-table';
import 'react-table/react-table.css'
import './App.css';

export default class App extends Component {

  constructor (props) {
    super(props) 
    this.state = {
      status: 'waiting',
      table: {
        columns: [],
        data: []
      },
      message: 'Waiting for file input...'
    }
    this.optionSelect = this.optionSelect.bind(this)
    this.parseFile = this.parseFile.bind(this)
  }

  optionSelect(selection, title) {
    if (this.state.status === 'ready') {
      fetch('http://localhost:3030/listitems?key=' + selection)
      .then( r => r.json() )
      .then( r => {
        let columns = Object.keys(r.list[0]).map(key => {
          if (r.list[0][key] instanceof Array) {
            return { 
              Header: key, 
              Cell: <button>View {key}</button> }
          }
          return { Header: key, accessor: key };
        });
        console.log(r.list)
        this.setState({ 
          table: { columns: columns, data: r.list },
          message: "Viewing " + title
        })
      })
    }
  }

  parseFile(path) {
    fetch('http://localhost:3030/parse/', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
            cmd: 'parseCfg',
            cfgFile: path
        })
    })
    .then( r => r.json() )
    .then( (r) => {
        if (r.status === "ready") {
          this.setState({status: 'ready', message: 'Ready...'})      
        }
    })
  }

  render() {
    return (
      <div className="App">
        <Navigation onSubmitFile={this.parseFile} message={this.state.message} />
        <div className="row">
          <Sidebar onSelect={this.optionSelect} />
          <div className="main-pane">
              <ReactTable data={this.state.table.data} columns={this.state.table.columns} />
          </div>
        </div>
      </div>
    );
  }
}

export class Navigation extends React.Component {

  render () {
      let items = ['1', '2', '3']
      items = items.map( item => <div key={item}>{item}</div> )
      return (
          <div className="navigation-bar">
              <nav>{items}</nav><span>{this.props.message}</span>
              <FileInput onSubmitFile={(path) => this.props.onSubmitFile(path)}/>
          </div>
      )
  }
}

export class FileInput extends React.Component {
  
  constructor(props) {
    super(props)
    this.state = {
      enabled: false,
      filePath: '/var/cisco-internet.cfg'
    }
    this.handleChange = this.handleChange.bind(this)
    this.submitFile = this.submitFile.bind(this)
  }

  handleChange(ev) {
    this.setState({filePath: ev.target.value})
  }

  submitFile(ev) {
    ev.preventDefault()
    this.props.onSubmitFile(this.state.filePath)
  }
  render() {
    return (
      <div className="file-input">
        Ruta del archivo: <br />
        <form onSubmit={this.submitFile}>
            <input type="text" value={this.state.filePath} onChange={this.handleChange} disabled={ this.state.disabled } />    
        </form>
      </div>
    )
  }
}

export class Sidebar extends React.Component {
  render() {
      let items = [
          {name: 'Objects', value: 'objects'}, 
          {name: 'Objects Groups', value: 'objectgroups'}, 
          {name: 'Routes', value: 'routes'},
          {name: 'Interfaces', value: 'interfaces'},
          {name: 'Users', value: 'users'},
          {name: 'Not Parsed', value: 'notparsed'},
      ];

      items = items.map(item => {
        return (
          <div key={item.value} onClick={() => this.props.onSelect(item.value, item.name)} className="side-item">
            {item.name}
          </div>
        )
      })
      return (
      <div className="sidebar">
          {items}
      </div>);
  }
}
