$.ajax({
    url: '/',
    type: 'POST',
    data: {cmd:"parseTest"},
    success: function(response){
        console.log(response.rules.filter)
        for (rule of response.rules.filter){
            $('#right-pane').append(`
            <div class="row">
                <div class="col-1 rule ruleNumber">${rule.number}</div>
                <div class="col-1 rule ruleAction">${rule.action}</div>
                <div class="col-2 rule ruleAccessList">${rule.acl}</div>
                <div class="col-1 rule ruleProtocol">${rule.protocol}</div>
                <div class="col-1 rule ruleSource">${rule.srcAddress}</div>
                <div class="col-1 rule ruleSourcePort">${rule.srcPort}</div>
                <div class="col-1 rule ruleDest">${rule.dstAddress}</div>
                <div class="col-1 rule ruleDestPort">${rule.dstPort}</div>
                <div class="col-2 rule ruleComment">${rule.comment}</div>
                <div class="col-1 rule ruleStatus">${rule.status}</div>
            </div>`)
        }
        console.log(response.notparsed)
        // console.log(response)
    },
    error: function(xhr,errmsg,err){
        console.log(xhr.status + ": " + xhr.responseText);
    }
})