import React from 'react';

export class Sidebar extends React.Component {

    constructor (props) {
        super(props)
        this.fetchKey = this.fetchKey.bind(this)
    }

    fetchKey(ev) {
        console.log(ev)
    }

    render() {
        let items = [
            {name: 'Objects', value: 'objects'}, 
            {name: 'Objects Groups', value: 'objectgroups'}, 
            {name: 'Routes', value: 'routes'},
            {name: 'Interfaces', value: 'interfaces'},
            {name: 'Users', value: 'users'},
            {name: 'Not Parsed', value: 'notparsed'},
        ];
        items = items.map(item => <div key={item.value} onClick={() => this.fetchKey(item.value)} className="side-item">{item.name}</div>)
        return (<div className="sidebar">
            {items}
        </div>);
    }
}