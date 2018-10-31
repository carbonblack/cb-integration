/**
 * Created by zestep on 10/25/18.
 */
import React, { Component } from 'react';
import {Grid, Menu, Button, Input} from 'semantic-ui-react';
import _ from 'lodash';
class ConnectorMenu extends Component {

    constructor(props) {
       super(props);
       this.xmlrpcclient = props.xmlrpcclient;
       this.connectorname = props.connectorname;
       this.state = {selected: "",rpcreturn:"",methods:[],rpcparams:{},setparams:{}};
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
                this.setState({methods:value.filter(method => method.includes(this.connectorname))});
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

    handleItemClick = (e, {name}) => {
        var theparams={};
        if (name.includes("getResultFor")){
            theparams["hash"] = "string";
        }
        if (name.includes("executeBinaryQuery")) {
            theparams['query'] = "string";
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
        const {selected,rpcreturn,methods,rpcparams,setparams} = this.state;
        var rpcreturntype = typeof rpcreturn;
        var inputsection;
        if (rpcparams){
            inputsection = (<div>{_.map(rpcparams,(key,value) => (
                            <Input onChange={(e,data) => (this.handleSetParam(value,data))} label={value}/>
            ))}</div> );
        };
        var gobutton = (<div><Button name="Run" onClick={this.handleMethodCall}>Run</Button></div>);
        var modalcontent;
        if (rpcreturntype === 'string' || rpcreturntype === 'number') {
            modalcontent = (<div>{String(rpcreturn)}</div>);
        } else {
            modalcontent = (
            <div>{_.map(rpcreturn ,(returnpart) => (
                    <div>{String(returnpart)}</div>
        ))}</div>);
        };

        return (
         <Grid>
         <Grid.Column width={4}>
         <Menu fluid vertical tabular>
            <Menu.Header>Available Methods</Menu.Header>
            { _.map(methods,(method) => (
                <Menu.Item name={method} active={selected === method} onClick={this.handleItemClick} />
            ))}
            </Menu>
            </Grid.Column>
            <Grid.Column width={12}>
                    <Grid>
                    <Grid.Row><div>{inputsection}</div><div>{gobutton}</div></Grid.Row>
                    <Grid.Row><div>{modalcontent}</div></Grid.Row>
                    </Grid>
            </Grid.Column>
          </Grid>
        );
    }
}

export default ConnectorMenu