'use strict'
const fs2 = require('fs')
const isip = require('is-ip')
const Ajv = require('ajv')
const request = require('request')
const ajv = new Ajv()

// const f5bigip = ['/Common/tcp']

const declarationfile = process.argv[2]

ajv.addFormat('f5bigip', (item) => {
    const regex = RegExp(/^\x2f[^\x00-\x19\x22#'*<>?\x5b-\x5d\x7b-\x7d\x7f]+$/)
    // if (!f5bigip.includes(item) || !regex.test(item)) {
    if (!regex.test(item)) {
        return false
    }
    return true
})

ajv.addFormat('f5label', (item) => {
    const regex = RegExp(/^[^\x00-\x1f\x22#&*<>?\x5b-\x5d`\x7f]{0,64}$/)
    if (!regex.test(item)) {
        return false
    }
    return true
})
ajv.addFormat('f5remark', (item) => {
    const regex = RegExp(/^[^\x00-\x1f\x22\x5c\x7f]{0,64}$/)
    if (!regex.test(item)) {
        return false
    }
    return true
})

ajv.addFormat('f5ip', (item) => {
    // checking if IP split from RouteDomain is valid
    const ipsplit = item.split('%')
    const ip = ipsplit[0]
    const rd = Number(ipsplit[1]) || 0
    if (!isip(ip) || !Number.isInteger(rd)) {
        return false
    }
    return true
})

ajv.addFormat('f5pointer', (item) => {
    const regex = RegExp(/^((@|[0-9]+)|(([0-9]*\x2f)?((@|[0-9]+|[A-Za-z][0-9A-Za-z_]{0,63})\x2f)*([0-9]+|([A-Za-z][0-9A-Za-z_]{0,63}))))?#?$/)
    if (!regex.test(item)) {
        return false
    }
    return true
})
ajv.addFormat('f5base64', (item) => {
    const regex = RegExp(/^([0-9A-Za-z/+_-]*|[0-9A-Za-z/+_-]+={1,2})$/)
    if (!regex.test(item)) {
        return false
    }
    return true
})
ajv.addFormat('f5name', (item) => {
    const regex = RegExp(/^([A-Za-z][0-9A-Za-z_]{0,63})?$/)
    if (!regex.test(item)) {
        return false
    }
    return true
})
ajv.addFormat('f5long-id', (item) => {
    const regex = RegExp(/^[^\x00-\x20\x22'<>\x5c^`|\x7f]{0,255}$/)
    if (!regex.test(item)) {
        return false
    }
    return true
})


const getSchema = (callback) => {
    const url = 'https://raw.githubusercontent.com/F5Networks/f5-appsvcs-extension/master/schema/latest/as3-schema.json'
    
    request({ url, json: true }, (error, { body }) => {
        if (error){
            callback('Unable to get schema from github')
        } else {
            callback('',body)
        }
    })
}

const validate = getSchema( (error, data) => {
    if (error) {
        return console.log(error)
    }

    if (!declarationfile){
        throw 'No file found'
    } else {
        const as3 = fs2.readFileSync(declarationfile)
        const valid = ajv.validate(data, JSON.parse(as3))

        if (!valid) {
            console.error(ajv.errors)
            throw 'Validation Failed'
        } else {
            console.log('valid')
        }
    }

})

