import React, { Component } from 'react';
import {Segment,Header,Table, Modal, Button, Grid} from 'semantic-ui-react';
import './App.css';
import _ from 'lodash';
import ConnectorMenu from './ConnectorMenu.js';
import xmlrpc from 'xmlrpc';

class App extends Component {
  constructor(props) { 
       super(props);
       this.state = {data:{},time: new Date(),error:null,allProcessMethods:[],loading:true,modalopen:false};
       this.xmlrpcclient = xmlrpc.createClient({ host: 'localhost', port: 5000, cookies: true, path: '/RPC2'})
       console.log("RESTARTING")
  }
  tick() {
      const {modalopen} = this.state;
      if (modalopen) {
         console.log("MODAL IS OPEN, not ticking");
        return
      } else {
          console.log("MODAL IS NOT OPEN, TICKING")
      }
      this.xmlrpcclient.methodCall('system.listMethods', [], (error, value) => {
            if (error) {
                console.log('error listing system methods:', error);
                console.log('req headers:', error.req && error.req._header);
                console.log('res code:', error.res && error.res.statusCode);
                console.log('res body:', error.body);
            } else {
                //console.log(value);
                this.setState({allProcessMethods:value.filter( v => v.includes(".getAllProcessInfo"))});
                //allProcessMethods = value.filter(v => v.includes(".getAllProcessInfo"));
                //console.log("Found process methods",allProcessMethods);
            }
      });
      //this.setState({data:[]});
      var allProcessMethods = this.state.allProcessMethods;
      var tempdata = this.state.data;
      console.log("The current getProcessInfo methods are:",allProcessMethods);
      var x;
      for (x in allProcessMethods) {

           this.xmlrpcclient.methodCall(allProcessMethods[x], [], (error, value) => {
                if (error) {
                    console.log("trying to call: ",allProcessMethods[x]);
                    console.log('error calling all process methods:', error);
                    console.log('req headers:', error.req && error.req._header);
                    console.log('res code:', error.res && error.res.statusCode);
                    console.log('res body:', error.body);
                } else {
                            tempdata[allProcessMethods[x]] =  value;
                            this.setState({data:tempdata});
                            console.log("this.state is now",this.state);
                            this.setState({loading:false});
                }
            });
      }
      this.setState({time:new Date()});
    }

  componentDidMount() {
      this.tick();
      this.interval = setInterval(() => this.tick(),7770);
  }

  componentWillUnmount() {
      clearInterval(this.interval);
  }

  setModalOpen = (synthevent,d) => {

  }

  render() {
    const {loading,data,modalopen} = this.state;
    var tempdata = [];
    var x;
    var y;
    for(x in data){
        for (y in data[x]) {
            tempdata = tempdata.concat(data[x][y]);
        }
    }
    console.log("TEMPDATA:",tempdata);
    var body,button;
    if (loading) {
        body = (<Table.Body/>);
    } else if (tempdata.length > 0) {
        button = (<Button onClick={(synthevent,d) => this.setState({modalopen:true})}>Control Connector</Button>);
        body = (<Table.Body>{_.map(tempdata, datum => (
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
                                        <Modal onClose={(synthevent,d) => this.setState({modalopen:false})} trigger={button}>
                                            <div className="modal-content"> <ConnectorMenu xmlrpcclient={this.xmlrpcclient} connectorname={datum['name']}/> </div>
                                        </Modal>
                                    </Table.Cell>
                                </Table.Row>
                ))}</Table.Body>);
    }

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
           {body}
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
