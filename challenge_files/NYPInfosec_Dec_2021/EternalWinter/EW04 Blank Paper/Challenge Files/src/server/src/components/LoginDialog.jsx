import React, { useState } from "react";
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


export default function LoginDialog({loggedIn, setLoggedIn, setRefresh}) {

    const [status, setStatus] = useState("");
    const [open, setOpen] = useState(false);
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");

    const handleClickOpen = () => {
        setOpen(true);
    };

    const handleClose = () => {
        setOpen(false);
    };


    function validateForm() {
        return username.length > 0 && password.length > 0;
    }
    const login = async () =>{
        const url ="/api/login"
        const body = {
            auth:{
                name: username,
                password: password
            }
        }
        const data = await(await fetch(url, {
            method: 'POST', // *GET, POST, PUT, DELETE, etc.
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
        console.log(data)
        if(data.ok == true)
        {
            localStorage.setItem("name","user")
            localStorage.setItem("password", "pwd")
            setStatus({
                severity: "success",
                message: "Logged In"
            })
            setLoggedIn(true)
            setTimeout(()=>setStatus(""), 1000)
            setRefresh(new Date())
            setOpen(false)
        }
        else
        {
            setStatus({
                severity: "error",
                message: "Failed"
            })
        }
        
    }

    return (
        !loggedIn ? 
        <div>
        <Button color="inherit" onClick={handleClickOpen}>Login</Button>
        <Dialog open={open} onClose={handleClose} aria-labelledby="form-dialog-title">
            <DialogTitle id="form-dialog-title">Login</DialogTitle>
            <DialogContent>
            <TextField
                autoFocus
                margin="dense"
                id="name"
                label="Username"
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                fullWidth
            />
            <TextField
                autoFocus
                margin="dense"
                id="password"
                label="Password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                fullWidth
            />
            </DialogContent>
            <DialogActions>
            <Button onClick={handleClose} color="primary">
                Cancel
            </Button>
            <Button onClick={async () => await login()} color="primary">
                Login
            </Button>
            {
                status ?
                    <Alert severity={status.severity}>
                        {status.message}
                    </Alert>
                    : null
}
            </DialogActions>
        </Dialog>
        </div> : null
    );
}