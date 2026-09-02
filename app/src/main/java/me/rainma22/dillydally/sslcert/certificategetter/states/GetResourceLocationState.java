package me.rainma22.dillydally.sslcert.certificategetter.states;

import java.net.URI;

import org.json.JSONObject;

import me.rainma22.dillydally.sslcert.ResourceLocationResponse;
import me.rainma22.dillydally.sslcert.certificategetter.CertificateGetterContext;

public class GetResourceLocationState implements CertificateGetterState {

    @Override
    public void handle(CertificateGetterContext ctx) {
        var conf = ctx.getConf();
        try (var in = URI.create(conf.getServerUrl()).toURL().openStream()) {
            ctx.setResourceLocations(JSONObject.fromJson(
                    new String(in.readAllBytes()),
                    ResourceLocationResponse.class));
        } catch (Exception e) {
            ctx.updateError(e);
        }
    }

}
