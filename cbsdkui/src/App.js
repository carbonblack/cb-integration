import React, { Component } from 'react';
import {Table, Modal, Button, Header, Menu} from 'semantic-ui-react';
//import supervisord from 'supervisord';
import './App.css';
import _ from 'lodash'
import xmlrpc from 'xmlrpc';

class App extends Component {
  constructor(props) { 
       super(props);
       this.state = {data:{},time: new Date(),error:null}
       this.xmlrpclient = xmlrpc.createClient({ host: 'localhost', port: 5000, cookies: true, path: '/RPC2'})
  }
  tick() { 
      this.setState(prevState => ({
            time: new Date()
      }));
      this.xmlrpclient.methodCall('supervisor.getAllProcessInfo', [], (error, value) => {
            if (error) {
                console.log('error:', error);
                console.log('req headers:', error.req && error.req._header);
                console.log('res code:', error.res && error.res.statusCode);
                console.log('res body:', error.body);
            } else {
                console.log(value);
                this.setState({data:value});
            }
      });
}

  componentDidMount() { 
      this.interval = setInterval(() => this.tick(),7770);
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
                                    "manipulate": "Manipulate"
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
                                        {datum['statename']}
                                    </Table.Cell>
                                    <Table.Cell collapsing>
                                    <Modal trigger={<Button>manipulate</Button>}>
                                    <Modal.Header>{datum['name']}</Modal.Header>
                                    <Modal.Content>
                                    <Menu>
                                        { .map(this.listAllMethodsForConnector(datum['name']),methodName) => (
                                            <Menu.Item name={methodName} active={}>


                                            </Menu.Item>
                                            )
                                        }
                                    </Menu>
                                    </Modal.Content>
                                    </Modal>
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
