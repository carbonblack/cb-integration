import React, { Component } from 'react';
import {Segment,Header,Table, Modal, Button, Grid} from 'semantic-ui-react';
//import supervisord from 'supervisord';
import './App.css';
import _ from 'lodash';
import ConnectorMenu from './ConnectorMenu.js';
import xmlrpc from 'xmlrpc';

class App extends Component {
  constructor(props) { 
       super(props);
       this.state = {data:{},time: new Date(),error:null}
       this.xmlrpcclient = xmlrpc.createClient({ host: 'localhost', port: 5000, cookies: true, path: '/RPC2'})
  }
  tick() { 
      this.setState(prevState => ({
            time: new Date()
      }));
      this.xmlrpcclient.methodCall('supervisor.getAllProcessInfo', [], (error, value) => {
            if (error) {
                console.log('error:', error);
                console.log('req headers:', error.req && error.req._header);
                console.log('res code:', error.res && error.res.statusCode);
                console.log('res body:', error.body);
            } else {
                console.log(value);
                this.setState({data:value.filter(v => ['redis','ui','nginx'].includes(v) === false )});
            }
      });
    }

  componentDidMount() {
      this.tick();
      this.interval = setInterval(() => this.tick(),7770);
  }

  componentWillUnmount() {
      clearInterval(this.interval);
  }

  render() {
    const {data} = this.state;
    return (
      <div className="App">
        <Grid>
        <Grid.Row height={4}>
              <Grid.Column width={4}/>
              <Grid.Column width={8}><Segment inverted >
                                    <Header as="h1" inverted  >Cb Connector Management UI</Header>
                                    </Segment>
              </Grid.Column>
              <Grid.Column width={4}/>
          </Grid.Row>
        <Grid.Row height={10}>
        <Grid.Column width={4} />
        <Grid.Column width={8}>
        <Table celled  >
         <Table.Header fullWidth>
                      <Table.Row>
                                {_.map({
                                    "name": "Connector Name",
                                    "description": "Description",
                                    "state": "State",
                                    "manipulate": "Options"
                                }, (k, v) => (
                                    <Table.HeaderCell>{k}</Table.HeaderCell>))
                                }
                      </Table.Row>
          </Table.Header>
          <Table.Body >
                {_.map(data, (datum) => (
                      <Table.Row key={"key"-datum['pid'].toString()}>
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
                                    <Modal trigger={<Button >Control Conector</Button>}>
                                        <div className="modal-content"><ConnectorMenu xmlrpcclient={this.xmlrpcclient} connectorname={datum['name']}/></div>
                                    </Modal>
                                    </Table.Cell>
                                </Table.Row>
                ))}
          </Table.Body>
          <Table.Footer fullWidth>
          </Table.Footer>
          </Table>
          </Grid.Column>
          </Grid.Row>
          <Grid.Row height={2}/>
          </Grid>
      </div>
    );
  }
}

export default App;
