package com.amazon.cdk.helper;

import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.services.cloudformation.AmazonCloudFormation;
import com.amazonaws.services.cloudformation.AmazonCloudFormationClientBuilder;
import com.amazonaws.services.cloudformation.model.AmazonCloudFormationException;
import com.amazonaws.services.cloudformation.model.GetTemplateRequest;
import com.amazonaws.services.cloudformation.model.GetTemplateResult;
import com.amazonaws.services.cloudformation.model.ListStacksResult;
import com.amazonaws.services.cloudformation.model.StackSummary;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class CFNHelperSingleton {
    private static CFNHelperSingleton instance = new CFNHelperSingleton();
    private Map<String, AmazonCloudFormation> cfnPerRegionMap = new HashMap<>();

    private CFNHelperSingleton() {
    }

    public static CFNHelperSingleton getInstance() {
        return instance;
    }

    private AmazonCloudFormation getCfnClient(String region) {
        return cfnPerRegionMap.computeIfAbsent(region, k -> AmazonCloudFormationClientBuilder.standard()
                .withCredentials(new DefaultAWSCredentialsProviderChain())
                .withRegion(region).build());
    }

    public Map<String, Object> getExistingStackParameters(String stackName, String region) throws IOException {
        AmazonCloudFormation client = getCfnClient(region);
        try {
            GetTemplateResult result = client.getTemplate(new GetTemplateRequest().withStackName(stackName));
            String template = result.getTemplateBody();
            return new ObjectMapper(new YAMLFactory()).readValue(template, Map.class);
        } catch (AmazonCloudFormationException e) {
            if (e.getMessage().contains("does not exist")) {
                return null;
            } else {
                throw e;
            }
        }
    }

    public List<StackSummary> listStacks(String region) {
        AmazonCloudFormation client = getCfnClient(region);
        ListStacksResult result = client.listStacks();
        return result.getStackSummaries();
    }
}