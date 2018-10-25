/**
 * Created by zestep on 10/25/18.
 */
import React, { Component } from 'react';
import {Table, Modal, Button, Header, Menu} from 'semantic-ui-react';
import _ from 'lodash';
class ConnectorMenu extends Component {

    constructor(props) {
       super(props);
       this.xmlrpclient = props.xmlrpclient;
       this.connectorname = props.connectorname;
       this.state = {selected: "",rpcreturn:"Nothing yet"};
    }

    listAllMethodsForConnector() {
        this.xmlrpclient.methodCall(this.connectorname+".listAllMethods", [], (error, value) => {
            if (error) {
                console.log("Connctor name is "+this.connectorname);
                console.log('error:', error);
                console.log('req headers:', error.req && error.req._header);
                console.log('res code:', error.res && error.res.statusCode);
                console.log('res body:', error.body);
                return [];
            } else {
                console.log(value);
                return value;
            }
        });
    }

    handleItemClick(e, name) {
        this.setState({selected: name});
        this.xmlrpclient.methodCall(this.connectorname + "." + name, [], (error, value) = > {
            if (error) {
                console.log("Connctor name is " + this.connectorname);
                console.log("Method name is : " + name)
                console.log('error:', error);
                console.log('req headers:', error.req && error.req._header);
                console.log('res code:', error.res && error.res.statusCode);
                console.log('res body:', error.body);
                return [];
            } else {
                console.log(value);
                this.setState({rpcreturn:value});
            }
        });
    }

    render() {
        const {selected,rpcreturn} = this.state;
        return (
         <Grid>
         <Grid.Column width={4}>
         <Menu fluid vertical tabular>
                <Menu.Header>Available Methods</Method.Header>
            {_.map(this.listAllMethodsForConnector(),method) => (
                <Menu.Item name={method} active={selected === method} onClick={this.handleItemClick} />
                </Menu.Item>
            )}
         </Menu>
            </Grid.Column>
            <Grid.Column
                    {rpcreturn}
            <Grid.Column>
        );
    }
}

export default ConnectorMenu