import React, { Component, useEffect, useState } from 'react'
import ListItem from '@material-ui/core/ListItem';
import ListItemText from '@material-ui/core/ListItemText';

function MessageList({refresh}) {
    var [messages, setMessages] = useState([])
    
    const getMessages = async () =>{
        const params = {
            "name": localStorage.getItem("name"),
            "password": localStorage.getItem("password")
        }
        const url = "/api/message?" + new URLSearchParams(params)
        let data = await (await fetch(url, {
            method: 'GET', // *GET, POST, PUT, DELETE, etc.
            mode: 'cors', // no-cors, *cors, same-origin
            cache: 'no-cache', // *default, no-cache, reload, force-cache, only-if-cached
            credentials: 'same-origin', // include, *same-origin, omit
            headers: {
                'Content-Type': 'application/json'
                // 'Content-Type': 'application/x-www-form-urlencoded',
            },
            redirect: 'follow', // manual, *follow, error
            referrerPolicy: 'no-referrer', // no-referrer, *no-referrer-when-downgrade, origin, origin-when-cross-origin, same-origin, strict-origin, strict-origin-when-cross-origin, unsafe-url
            // ody data type must match "Content-Type" header
        })).json()
        if(data.error)
        {
            setMessages([{"message": "Please login to see the messages"}])
        }
        else
        {
            setMessages(data)
        }
            
        }
    useEffect(()=>{
        getMessages()
    }, [refresh])
    return (
        <>
            {messages.length ? messages.map(item => {
                console.log("test")
                return (<ListItem>
                    <ListItemText primary={item.message} />
                </ListItem>)
            }
            ) : null}
        </>
    );
}

export default MessageList