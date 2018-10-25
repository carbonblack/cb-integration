/**
 * Created by zestep on 10/25/18.
 */
import React, { Component } from 'react';
import {Grid, Menu} from 'semantic-ui-react';
import _ from 'lodash';
class ConnectorMenu extends Component {

    constructor(props) {
       super(props);
       this.xmlrpcclient = props.xmlrpcclient;
       this.connectorname = props.connectorname;
       this.state = {selected: "",rpcreturn:"",methods:[]};
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

    handleItemClick = (e, {name}) => {
        this.setState({selected: name});
        //var methodcall = this.connectorname + "." + name;
        //console.log("Trying to call ",methodcall);
        this.xmlrpcclient.methodCall(name, [], (error, value) => {
            if (error) {
                console.log("Method name is : " + name);
                console.log('error:', error);
                console.log('req headers:', error.req && error.req._header);
                console.log('res code:', error.res && error.res.statusCode);
                console.log('res body:', error.body);
                this.setState({rpcreturn:String(error)});
            } else {
                console.log(value);
                this.setState({rpcreturn:value});
            }
        });
    }

    render() {
        const {selected,rpcreturn,methods} = this.state;
        console.log(methods);
        return (
         <Grid>
         <Grid.Column width={4}>
         <Menu fluid vertical tabular>
            <Menu.Header>Available Methods</Menu.Header>
            { _.map( methods , (method) => (
                <Menu.Item name={method} active={selected === method} onClick={this.handleItemClick} />
            ))}
            </Menu>
            </Grid.Column>
            <Grid.Column width={12}>
                {String(rpcreturn)}
            </Grid.Column>
          </Grid>
        );
    }
}

export default ConnectorMenu