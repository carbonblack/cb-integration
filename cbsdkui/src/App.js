import React, { Component } from 'react';
import {Table} from 'semantic-ui-react';
import supervisord from 'supervisord';
import './App.css';
import _ from 'lodash'

class App extends Component {
  constructor(props) { 
       super(props);
       this.state = {data:{},time: new Date(),error:null}
       this.supervisord_client = supervisord.connect('http://localhost:5000/supervisor');
  }
  tick() { 
      this.setState(prevState => ({
            time: new Date()
      }));
      this.supervisord_client.getAllProcessInfo((err,result) => { 
          this.setState({data:result,error:err})
          console.log(err);
          console.log(result);
      });
  }
  componentDidMount() { 
      this.interval = setInterval(() => this.tick(),1000);
  }
  componentWillUnmount() { 
      clearInterval(this.interval);
  }
  render() {
    const {data} = this.state;
    return (
      <div className="App">
        <Table celled>
         <Table.Header fullWidth>
                      <Table.Row>
                                {_.map({
                                    "name": "Name",
                                    "description": "Description",
                                    "state": "State",
                                    "log" : "Log"
                                }, (k, v) => (
                                    <Table.HeaderCell>{k}</Table.HeaderCell>))
                                }
                      </Table.Row>
          </Table.Header>
          <Table.Body>
                {_.map(data, (datum) => (
                      <Table.Row key={datum['pid'].toString()}>
                                    <Table.Cell collapsing>
                                        {datum['name']}
                                    </Table.Cell>
                                    <Table.Cell collapsing>
                                     {datum['description']}
                                    </Table.Cell>
                                    <Table.Cell collapsing>
                                        {datum['StateName']}
                                    </Table.Cell>
                                    <Table.Cell collapsing>
                                        {datum['log']}
                                    </Table.Cell>
                                </Table.Row>
                ))}
          </Table.Body>
          <Table.Footer fullWidth>
          </Table.Footer>
          </Table>
      </div>
    );
  }
}

export default App;
