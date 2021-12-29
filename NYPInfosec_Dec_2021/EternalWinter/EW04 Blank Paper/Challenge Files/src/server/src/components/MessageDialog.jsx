import React, { useState, useEffect } from "react";
import Button from '@material-ui/core/Button';
import TextField from '@material-ui/core/TextField';
import MuiAlert from '@material-ui/lab/Alert';
import Dialog from '@material-ui/core/Dialog';
import DialogActions from '@material-ui/core/DialogActions';
import DialogContent from '@material-ui/core/DialogContent';
import DialogTitle from '@material-ui/core/DialogTitle';

function Alert(props) {
    return <MuiAlert elevation={6} variant="filled" {...props} />;
  }


export default function MessageDialog({loggedin, setRefresh}) {

    const [open, setOpen] = useState(false);
    const [message, setMessage] = useState("");
    const [status, setStatus] = useState("");

    const handleClickOpen = () => {
        setOpen(true);
    };

    const handleClose = () => {
        setOpen(false);
    };
    const CreateMessage = async () =>{
        const body = {
            "auth": {
                "name": localStorage.getItem("name"),
                "password": localStorage.getItem("password")
            },
            message: {"message" : message}
        }
        const url = "/api/message"
        const data = await(await fetch(url, {
            method: 'PUT', // *GET, POST, PUT, DELETE, etc.
            mode: 'cors', // no-cors, *cors, same-origin
            cache: 'no-cache', // *default, no-cache, reload, force-cache, only-if-cached
            credentials: 'same-origin', // include, *same-origin, omit
            headers: {
                'Content-Type': 'application/json'
                // 'Content-Type': 'application/x-www-form-urlencoded',
            },
            redirect: 'follow', // manual, *follow, error
            referrerPolicy: 'no-referrer',
            body: JSON.stringify(body) // no-referrer, *no-referrer-when-downgrade, origin, origin-when-cross-origin, same-origin, strict-origin, strict-origin-when-cross-origin, unsafe-url
            // ody data type must match "Content-Type" header
        })).json()
        setStatus({message:"Message added", severity:"info"})
        setTimeout(()=>setStatus(""), 1000)
        setRefresh(new Date())
    }

    useEffect(()=>{}, [loggedin])

    return (
        <>
            { loggedin ? <div><Button color="inherit" onClick={handleClickOpen}>Create</Button>
        <Dialog open={open} onClose={handleClose} aria-labelledby="form-dialog-title">
            <DialogTitle id="form-dialog-title">Create Message</DialogTitle>
            <DialogContent>
            <TextField
                autoFocus
                margin="dense"
                id="name"
                label="message"
                type="text"
                value={message}
                onChange={(e) => setMessage(e.target.value)}
                fullWidth
            />
            </DialogContent>
            <DialogActions>
                <Button onClick={handleClose} color="primary">
                    Cancel
                </Button>
                <Button onClick={async ()=> await CreateMessage()} color="primary">
                    Create
                </Button>
                { status ? <Alert severity={status.severity}> {status.message} </Alert> : null}
            </DialogActions>
        </Dialog>
        </div>
        : null}
        </>
    );
}