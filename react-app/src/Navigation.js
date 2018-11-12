import React from 'react'

export class Navigation extends React.Component {

    constructor(props) {
        super(props)
        this.state = {
            status: 'waiting',
            filePath: '/var/cisco-internet.cfg'
        }
        this.handleChange = this.handleChange.bind(this)
        this.submitFile = this.submitFile.bind(this)
    }

    handleChange(ev) {
        this.setState({filePath: ev.target.value})
    }

    submitFile(ev) {
        fetch('http://localhost:3030/parse/', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({
                cmd: 'parseCfg',
                cfgFile: this.state.filePath
            })
        })
        .then( r => r.json() )
        .then( (r) => {
            if (r.status === "ready") {
                console.log("Ready to fetch data...")       
            }
        })
        ev.preventDefault()
    }

    render () {
        let items = ['1', '2', '3']
        items = items.map( item => <div key={item}>{item}</div> )
        return (
            <div className="navigation-bar">
                <nav>{items}</nav>

                <div className="file-input">
                    Ruta del archivo: <br />
                    <form onSubmit={this.submitFile}>
                        <input type="text" value={this.state.filePath} onChange={this.handleChange} />    
                    </form>
                </div>
            </div>
        )
    }

}