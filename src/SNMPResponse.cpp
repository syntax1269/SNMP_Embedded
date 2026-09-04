#include "include/SNMPResponse.h"

bool SNMPResponse::addResponse(const VarBind& response){
    this->emplace_back(response);
    return true;
}

bool SNMPResponse::addErrorResponse(const VarBind& response){
    int index = this->size() + 1;
    this->emplace_back(response);
    
    if(response.errorStatus != NO_ERROR){
        this->errorStatus.errorStatus = response.errorStatus;
        this->errorIndex.errorIndex = index;
    }
    return true;
}

bool SNMPResponse::setGlobalError(SNMP_ERROR_STATUS error, int index, int override){
    if(this->errorStatus.errorStatus == NO_ERROR || (this->errorStatus.errorStatus != NO_ERROR && override)){
        this->errorStatus.errorStatus = error;
        this->errorIndex.errorIndex = index;
    }
    return true;
}