import { useState, useEffect } from 'react';
import { makeStyles } from '@material-ui/core/styles';
import {AppBar, Toolbar, Typography, Button, Paper} from "@material-ui/core"
import MenuIcon from "@material-ui/icons/Menu"
import LoginDialog from "./components/LoginDialog"
import MessageList from "./components/MessageList"
import List from '@material-ui/core/List';
import MessageDialog from './components/MessageDialog';



const useStyles = makeStyles((theme) => ({
  root: {
    flexGrow: 1,
  },
  menuButton: {
    marginRight: theme.spacing(2),
  },
  title: {
    flexGrow: 1,
  }
}));


function App() {
  var [refresh, setRefresh] = useState(0);
  var classes = useStyles();
  var [loggedIn, setLoggedIn] = useState(false);
  var checkLogin = ()=>{
    if(localStorage.getItem("name") && localStorage.getItem("password"))
    {
      console.log('test2')
      setLoggedIn(true)
    }
    else
    {
      setLoggedIn(false)
    }
  }

  var signOut = ()=>{
    localStorage.removeItem("name")
    localStorage.removeItem("password")
    setLoggedIn(false)
  }
  useEffect(checkLogin, [loggedIn, localStorage["name"], localStorage["password"]])
  return (
    <div className={classes.root}>
    <AppBar position="static">
    <Toolbar>
    <Paper variant="outlined">
      <img src="EW_Logo.png" width="50vh"/>
      </Paper>
      <Typography variant="h6" className={classes.title}>
        
      </Typography>
      <MessageDialog loggedin={loggedIn} setRefresh={setRefresh}/>
      <Button onClick={()=>setRefresh(new Date().getTime())} color="inherit">
                Refresh
      </Button>
      <LoginDialog loggedIn={loggedIn} setLoggedIn={setLoggedIn} setRefresh={setRefresh}/>
      {
        loggedIn ?
      <Button onClick={()=>signOut()} color="inherit">
                Sign Out
      </Button>: null
      }
    </Toolbar>
  </AppBar>
  
    <List component="nav" aria-label="main mailbox folders">
      {<MessageList refresh={refresh}/>}
    </List>
    </div>
  );
}

export default App;
