var snmp = require ("net-snmp");
const express = require('express');
const bodyParser = require('body-parser');

const app = express();
const port = 3000;
const baseUrl = `http://localhost:${port}`;

// configurando o middleware
app.use(bodyParser.json());

//get -> /
app.get("", (req, res)=>{
    console.log("Endpoint raiz...");
});

//get -> /oid
app.get("/oid", (req, res)=>{

    const { userName, contextName, authKey, privKey, oid, ipAddress } = req.query;

    var options = {
        port: 161,
        retries: 0,
        timeout: 5000,
        transport: "udp4",
        trapPort: 162,
        version: snmp.Version3,
        backwardsGetNexts: true,
        reportOidMismatchErrors: false,
        idBitsSize: 32,
        context: contextName
    };
    
    var user = {
        name: userName,
        level: snmp.SecurityLevel.authPriv,
        authProtocol: snmp.AuthProtocols.sha,
        authKey: authKey,
        privProtocol: snmp.PrivProtocols.aes,
        privKey: privKey 
    };

    var session = snmp.createV3Session (ipAddress, user, options);

    var oids = [oid];
    
    session.get (oids, function (error, varbinds) {
        const result = [];
        if (error) {
            res.json({error: error.toString()});
        } else {
            for (var i = 0; i < varbinds.length; i++) {
            
                if (snmp.isVarbindError (varbinds[i])){
                    res.json({error: snmp.varbindError(varbinds[i])});
                }               
                else{
                    let dataStringValue;

                    if (varbinds[i].value === snmp.ObjectType.OCTET_STRING){
                        dataStringValue = varbinds[i].value.toString('utf8');
                    }else {
                        dataStringValue = varbinds[i].value.toString();
                    }
                    result.push({oid: varbinds[i].oid, data: dataStringValue});
                }
            }
        }
        res.json(result);
    });
});

app.listen(port, () => {
    console.log(`Servidor executado com sucesso, na url: ${baseUrl}`);
});