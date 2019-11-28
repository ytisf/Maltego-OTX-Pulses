

from maltego_trx.entities import IPAddress, Domain, Phrase, Alias, Hashtag, Person, URL
from maltego_trx.transform import DiscoverableTransform
import maltego_trx as TRX

from otx_pulses import getPulses, _split_every_n


class IPToPulses(DiscoverableTransform):
    @classmethod
    def create_entities(cls, request, response):
        indicator = request.Value

        a = getPulses(indicator, "IPv4")

        if a is False:
            return
        for i in a:
            me = response.addEntity('maltego.Website', "%s" % i.name)
            me.setLinkColor('0xff00ff')
            me.addProperty('created_time', 'Pulse Creation Time', '', i.created)

            # response.addEntity(me)
            me.addProperty('modified_time', 'Pulse Modification Time', '', i.modified)
            if i.description is not '':
                desc = '\n'.join(_split_every_n(i.description, 40))
            else:
                desc = i.description

            if i.refs == []:
                me.setNote(desc)
            else:
                me.setNote("%s, \n\n %s." % (desc, ' '.join(i.refs)))

            for malware in i.malware_families:
                if malware == '':
                    continue
                response.addUIMessage(malware)
                j = response.addEntity('maltego.Hash', malware)
                j.addProperty('from_pulse', "Found in Pulse", "", i.name)

            for group in i.groups:
                if group == '':
                    continue
                j = response.addEntity('maltego.Organization', group)
                j.addProperty('from_pulse', "Found in Pulse", "", i.name)

            if i.adversary != '':
                j = response.addEntity('maltego.Organization', i.adversary)
                j.addProperty('adversary_from', "Adversary from Pulse", '', i.name)
