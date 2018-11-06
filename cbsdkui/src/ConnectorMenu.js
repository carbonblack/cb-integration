/**
 * Created by zestep on 10/25/18.
 */
import React, { Component } from 'react';
import {Segment,Grid,Table,Tab, Menu, Button, Input, Divider} from 'semantic-ui-react';
import _ from 'lodash';
import fs from 'file-system';
import path from 'path';
class ConnectorMenu extends Component {

    constructor(props) {
       super(props);
       this.xmlrpcclient = props.xmlrpcclient;
       this.connectorname = props.connectorname;
       this.state = {selected_tab:"connector",selected: "",rpcreturn:"",supervisormethods:[],methods:[],rpcparams:{},setparams:{}};
       this.listAllMethodsForConnector();
    }

    componentDidMount() {

    }

    listAllMethodsForConnector() {
        this.xmlrpcclient.methodCall("system.listMethods", [], (error, value) => {
            if (error) {
                console.log("Connctor name is "+this.connectorname);
                console.log('error:', error);
                console.log('req headers:', error.req && error.req._header);
                console.log('res code:', error.res && error.res.statusCode);
                console.log('res body:', error.body);
                this.setState({methods:[]});
            } else {
                console.log(value);
                this.setState({methods:value.filter(method => method.includes(this.connectorname)), supervisormethods:value.filter(method => method.includes("supervisor"))});
            }
        });
    }

    handleMethodCall = (e) => {
         const {selected, setparams } = this.state;
         var params = [];
         var i;
         for (i in setparams) {
             params.push(setparams[i]);
         }
         console.log("PARAMS ARE " + params);
         this.xmlrpcclient.methodCall(selected, params, (error, value) => {
            if (error) {
                console.log("Method name is : " + selected);
                console.log('error:', error);
                console.log('req headers:', error.req && error.req._header);
                console.log('res code:', error.res && error.res.statusCode);
                console.log('res body:', error.body);
                this.setState({rpcreturn:[String(error)]});
            } else {
                this.setState({rpcreturn:value});
            }
        });
    }

    handleFileUpload = (filelist) => {
        this.filelist = filelist;
        console.log("%v",filelist)
        //do something with the file to be uploaded
        /*var i = 0;
        for (i=0;i < filelist.length ; i++) {
            fs.writeFile(path.join(this.setparams['directory'],filelist[i].name), filelist[i], function (err) {
                if (err) throw err;
                    console.log('Saved! ',filelist[i].name);
                });
        }*/
    }

    handleTabClick = (e,{name}) => {
            this.setState({selected_tab:name});
    }

    handleItemClick = (e, {name}) => {
        var theparams={};
        if (name.includes("getResultFor")){
            theparams["hash"] = "string";
        }
        if (name.includes("executeBinaryQuery")) {
            theparams['query'] = "string";
        }
        if (name.includes("upload")) {
            theparams['file'] = 'upload';
            theparams['directory'] = 'string';
        }
        this.setState({rpcreturn:{} , selected: name, rpcparams: theparams, setparams:{}});
    }

    handleSetParam = (name,value) => {
            console.log("VALUE IS ",value);
            console.log("param Name is ",name);
            var params = this.state.setparams;
            params[name] = value.value;
            this.setState({setparams:params});
    }

    render() {
        const {selected,rpcreturn,methods,rpcparams,setparams,supervisormethods} = this.state;
        var rpcreturntype = typeof rpcreturn;
        var inputsection;
        console.log("RPC PARAMS ARE ",rpcparams);
        console.log("RPC return is",rpcreturn);
        if (rpcparams){
            inputsection = (<div>{_.map(rpcparams,(key,value) => (
                            key.includes("upload") ? <div><Input label={"Upload file"} oncChange={this.handleFileUpload} type={"file"}/><Button name="Upload" onClick={this.handleFileUpload}>Upload</Button></div> : <Input label={value} onChange={(e,data) => (this.handleSetParam(value,data))} />
            ))} </div> );
        } else {
            inputsection = (<div>No input required.</div>);
        }
        var gobutton = (<div><Button name="Run" onClick={this.handleMethodCall}>Run</Button></div>);
        var modalcontent;
        if (rpcreturntype === 'string' || rpcreturntype === 'number') {
            modalcontent = (<div>{String(rpcreturn)}</div>);
        } else if (rpcreturn.constructor === Object){
                modalcontent = (<Table fluid striped><Table.Body>
                                    {_.map(rpcreturn, (value,key) => (
                                    <Table.Row> <Table.Cell > {key}:{value}</Table.Cell ></Table.Row>))}
                                </Table.Body></Table>);
        } else if (rpcreturn != "" ) {
                 modalcontent = (<Table fluid striped><Table.Body>
                                    {_.map(rpcreturn, (row) => (
                                    <Table.Row> <Table.Cell >{row}</Table.Cell ></Table.Row>))}
                                </Table.Body></Table>);
        }
        else {
            modalcontent = (<div>Nothing to display...yet</div> ) ;
        }
        const panes = [
            {menuItem: "connector",render: () => <Tab.Pane><Menu vertical >
                                                     { _.map(methods,(method) => (
                                                            <Menu.Item name={method} active={selected === method} onClick={this.handleItemClick}>{method.slice(this.connectorname.length+1)}</Menu.Item>
                                                        ))}</Menu>
                                                        </Tab.Pane>},
            {menuItem: "supervisor",render: () => <Tab.Pane><Menu vertical>
                                                     { _.map(supervisormethods,(method) => (
                                                            <Menu.Item name={method} active={selected === method} onClick={this.handleItemClick}>{method.slice("supervisor.".length)}</Menu.Item>
                                                        ))}</Menu>
                                                    </Tab.Pane>},
        ];
        return (
         <Grid  >
         <Grid.Column width={4} >
            <Tab panes={panes}/>
            </Grid.Column>
            <Grid.Column width={12}>
                    <Grid>
                    <Grid.Row height={3}><Grid.Column width={8}><div>{inputsection}</div></Grid.Column><Grid.Column width={1}/><Grid.Column width={1}><div>{gobutton}</div></Grid.Column></Grid.Row>
                    <Grid.Row height={1}/>
                    <Grid.Row height={6}><Grid.Column width={10}><div>{modalcontent}</div></Grid.Column></Grid.Row>
                    </Grid>
            </Grid.Column>
          </Grid>
        );
    }
}

export default ConnectorMenu