import React from 'react'

export class MainPane extends React.Component {

    render() {
        let lines = this.props.lines
        return (
            <div className="main-pane">
                <ul>
                    {lines}
                </ul>
            </div>
        )
    }
}