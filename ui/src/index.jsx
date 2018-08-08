import React from 'react';
import ReactDOM from 'react-dom';

const title = 'Cb Integration UI';

ReactDOM.render(
    <div>{title}</div>,
    document.getElementById('app')
);

module.hot.accept();