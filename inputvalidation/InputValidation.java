package amazon.rds.admin.service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import amazon.rds.admin.config.ConfigDescriptor;
import amazon.rds.admin.db.dao.ServerConfigUtils;
import amazon.rds.model.interfaces.common.TaggableResource;
import com.amazon.coral.service.ServiceUnavailableException;
import amazon.rds.admin.model.CustomerSubnetGroup;
import amazon.rds.admin.model.DbClusterOptionGroup;
import amazon.rds.admin.model.DbClusterParameterGroup;
import amazon.rds.admin.model.DbClusterSnapshot;
import amazon.rds.admin.model.DbInstance;
import amazon.rds.admin.model.DbInstanceBackup;
import amazon.rds.admin.model.DbSecurityGroup;
import amazon.rds.admin.model.EventSubscription;
import amazon.rds.admin.model.OptionGroup;
import amazon.rds.admin.model.ParameterGroup;
import amazon.rds.admin.model.ReservedDbInstance;
import amazon.rds.admin.service.internal.InternalEventSubscription;
import com.amazon.rds.dynamo.manager.TagsPropagationRetryClusterManager;
import com.amazonaws.services.rds.model.DBSubnetGroup;
import com.amazonaws.services.redshift.model.ClusterParameterGroup;
import com.google.common.annotations.VisibleForTesting;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import amazon.rds.admin.activity.AddTagsToResourceRequest;
import amazon.rds.admin.activity.ListTagsForResourceRequest;
import amazon.rds.admin.activity.RemoveTagsFromResourceRequest;
import amazon.rds.admin.activity.Tag;
import amazon.rds.admin.internal.client.RDSInternalClientHelper;
import amazon.rds.admin.model.DbCluster;
import amazon.rds.admin.model.DbSnapshot;
import amazon.rds.admin.region.RegionCache;
import amazon.rds.admin.service.cryo.CryoHelper;
import amazon.rds.admin.service.tagging.ResourceOwnershipValidator;
import amazon.rds.admin.tagging.TaggingHelper;
import amazon.rds.admin.tagging.adapter.model.RDSTaggingResourceTagMapping;
import amazon.rds.admin.tagging.exception.RDSTaggingAccessDeniedException;
import amazon.rds.admin.tagging.exception.RDSTaggingConcurrentAccessException;
import amazon.rds.admin.tagging.exception.RDSTaggingException;
import amazon.rds.admin.tagging.exception.RDSTaggingInternalIdMismatchException;
import amazon.rds.admin.tagging.exception.RDSTaggingInvalidParameterException;
import amazon.rds.admin.tagging.exception.RDSTaggingTooManyTagsException;
import amazon.rds.admin.utils.Arn;
import amazon.rds.admin.utils.ArnUtils;
import amazon.rds.events.EventLog;

import com.amazon.aws.platform.billing.tagset.manager.service.model.EntityNotFoundException;
import com.amazon.coral.service.InvalidParameterCombinationException;
import com.amazon.coral.service.InvalidParameterValueException;
import com.google.common.collect.Maps;

@Component
public class TaggingManagerImpl implements TaggingManager {

    // for some reason our connections to the tagging service sometimes get killed mid-request,
    // or possibly they're getting stale.
    // to prevent customers from getting internal failures, we need to retry tagging calls if they fail.
    private static int MAX_TRIES = 3;

    // this regex comes from the tagging service's documentation:
    // https://code.amazon.com/packages/AWSTagSetCommons/blobs/a313ec4c3dcb8556ba992241c7510fba9c6ce02b/--/src/com/amazon/aws/platform/billing/tagset/type/TagElement.java#L58-L58|L55
    private static final String VALID_TAG_CHARACTERS_REGEX = "^([\\p{L}\\p{Z}\\p{N}_.:/=+\\-@]*)$";
    @VisibleForTesting
    static final ConfigDescriptor<Boolean> CLUSTER_TAG_PROPAGATION_ENABLED =
            new ConfigDescriptor<>("TaggingManager", "ClusterTagPropagationEnabled", false);

    private final ResourceOwnershipValidator ownershipValidator;
    private final TaggingHelper taggingHelper;
    private final RDSInternalClientHelper rdsInternalClientHelper;
    private final RegionCache regionCache;
    private final TagsPropagationRetryClusterManager tagsPropagationRetryClusterManager;
    private final ServerConfigUtils serverConfigUtils;

    @Autowired
    public TaggingManagerImpl(
            ResourceOwnershipValidator ownershipValidator,
            TaggingHelper taggingHelper,
            RDSInternalClientHelper rdsInternalClientHelper,
            RegionCache regionCache,
            TagsPropagationRetryClusterManager tagsPropagationRetryClusterManager,
            ServerConfigUtils serverConfigUtils) {
        this.ownershipValidator = ownershipValidator;
        this.taggingHelper = taggingHelper;
        this.rdsInternalClientHelper = rdsInternalClientHelper;
        this.regionCache = regionCache;
        this.tagsPropagationRetryClusterManager = tagsPropagationRetryClusterManager;
        this.serverConfigUtils = serverConfigUtils;
    }

    @Override
    public void addTagsToResource(String customerId, AddTagsToResourceRequest request) {
        addTagsToResource(customerId, request, false);
    }

    @Override
    public void addTagsToResource(String customerId, AddTagsToResourceRequest request, boolean calledFromCryo) {
        throwIfTaggingIsDisabled();

        validateResourceName(request.getResourceName());

        final Arn arn = new Arn(request.getResourceName());

        verifyArn(customerId, arn);
        Map<String, String> addedTags = validateTagsToAdd(request.getTagsToAdd(), calledFromCryo);

        TaggableResource resource = validateResourceExistenceAndRetrieveResource(arn);

        if (calledFromCryo) {
            // AWS Backup is allowed to manipulate aws:backup: system tags
            if (!CryoHelper.validateAllCryoTags(addedTags.keySet())) {
                // And user tags on AWS Backup snapshots
                if (!CryoHelper.isCryoManagedSnapshot(resource)) {
                    throw new InvalidParameterValueException("AWS Backup is allowed only to manipulate user tags " +
                            "on AWS Backup snapshots.");
                }
            }
        }

        updateResource(customerId, arn, addedTags, null, getInternalId(arn, resource));
        // If the resource is a cluster we also need to propagate the tags to the storage resource
        if (isClusterTagPropagationEnabled() && isClusterTagPropagationSupportedForResource(arn, resource)) {
            DbCluster dbCluster = (DbCluster) resource;
            Arn immutableArn = ArnUtils.createImmutableArnForDbClusterByRegionName(arn.getRegion(), dbCluster);
            //updates the resource for storage
            try {
                updateResource(customerId, immutableArn, addedTags, null, null);
            } catch (Exception e) {
                scheduleRetryTagPropagation(dbCluster.getId());
            }
        }
    }

    private void scheduleRetryTagPropagation(long dbClusterId) {
        try {
            tagsPropagationRetryClusterManager.createClusterForRetry(dbClusterId);
        } catch (Exception e) {
            log().error("Retry Tag propagation could not be scheduled for cluster " + dbClusterId);
        }
    }

    @Override
    public void removeTagsFromResource(String customerId, RemoveTagsFromResourceRequest request) {
        removeTagsFromResource(customerId, request, false);
    }

    @Override
    public void removeTagsFromResource(String customerId, RemoveTagsFromResourceRequest request, boolean calledFromCryo) {
        throwIfTaggingIsDisabled();

        validateResourceName(request.getResourceName());

        final Arn arn = new Arn(request.getResourceName());

        verifyArn(customerId, arn);

        validateTagsToRemove(request.getTagsToRemove(), calledFromCryo);

        TaggableResource resource = validateResourceExistenceAndRetrieveResource(arn);

        if (calledFromCryo) {
            // AWS Backup is allowed to manipulate aws:backup: system tags
            if (!CryoHelper.validateAllCryoTags(new HashSet(request.getTagsToRemove()))) {
                // And user tags on AWS Backup snapshots
                if (!CryoHelper.isCryoManagedSnapshot(resource)) {
                    throw new InvalidParameterValueException("AWS Backup is allowed only to manipulate user tags " +
                            "on AWS Backup snapshots.");
                }
            }
        }

        updateResource(customerId, arn, null, request.getTagsToRemove(), getInternalId(arn, resource));
        if (isClusterTagPropagationEnabled() && isClusterTagPropagationSupportedForResource(arn, resource)) {
            DbCluster dbCluster = (DbCluster) resource;
            Arn immutableArn = ArnUtils.createImmutableArnForDbClusterByRegionName(arn.getRegion(), dbCluster);
            try {
                updateResource(customerId, immutableArn, null, request.getTagsToRemove(), null);
            } catch (Exception e) {
                scheduleRetryTagPropagation(dbCluster.getId());
            }
        }
    }

    private boolean isClusterTagPropagationSupportedForResource(final Arn arn, final TaggableResource resource) {
        if (arn.getResourceType() != Arn.ResourceType.DB_CLUSTER || ! (resource instanceof  DbCluster))
            return false;
        DbCluster dbCluster = (DbCluster) resource;
        return dbCluster.getCustomerDbClusterIdentifier().equals(arn.getCustomerResourceIdentifier());
    }

    @Override
    public void copyTags(String customerId, Arn fromArn, Arn toArn, boolean excludeReservedTags) {
        try {
            taggingHelper.copyTags(customerId, fromArn, toArn, excludeReservedTags, getInternalId(toArn));
        } catch (RDSTaggingException e) {
            log().error(String.format("Error copying tags from customerId %s, from ARN %s to ARN %s, excludeReservedTags: %s",
                    customerId, fromArn.toString(), toArn.toString(), Boolean.toString(excludeReservedTags)), e);
        }
    }

    @Override
    public void copyTagsWithFallback(String customerId, Arn fromArn, String fromTagSetId, Arn toArn, boolean excludeReservedTags) {
        try {
            taggingHelper.copyTagsWithFallback(customerId, fromArn, fromTagSetId, toArn, excludeReservedTags, getInternalId(toArn));
        } catch (RDSTaggingException e) {
            log().error(String.format("Error copying tags from customerId %s, from ARN %s [with fallback, tagSetId: %s] to ARN " +
                            "%s, excludeReservedTags: %s",
                    customerId, fromArn.toString(), fromTagSetId, toArn.toString(), Boolean.toString(excludeReservedTags)), e);
        }
    }

    @Override
    public void copyTagsWithNewOwner(String fromCustomerId, Arn fromArn,
                                     Arn toArn, boolean excludeReservedTags, String newOwnerCustomerId) {
        try {
            taggingHelper.copyTagsWithNewOwner(fromCustomerId, fromArn, toArn, excludeReservedTags, newOwnerCustomerId);
        } catch (RDSTaggingException e) {
            log().error(String.format("Error copying tags from customerId %s, " +
                            "from ARN %s to ARN %s [changing owner to %s], excludeReservedTags: %s",
                    fromCustomerId, fromArn.toString(), toArn.toString(), newOwnerCustomerId,
                    Boolean.toString(excludeReservedTags)), e);
        }
    }

    @Override
    public void copyTagsWithNewOwnerWithExceptions(final String fromCustomerId, final Arn fromArn, final Arn toArn,
                                                   boolean excludeReservedTags, final String newOwnerCustomerId) {
        try {
            taggingHelper.copyTagsWithNewOwner(fromCustomerId, fromArn, toArn, excludeReservedTags, newOwnerCustomerId);
        } catch (RDSTaggingInvalidParameterException e) {
            throw new InvalidParameterValueException(e.getMessage(), e);
        } catch (RDSTaggingAccessDeniedException | RDSTaggingConcurrentAccessException
                | RDSTaggingInternalIdMismatchException | RDSTaggingTooManyTagsException e) {
            throw new InvalidParameterCombinationException(e.getMessage(), e);
        } catch (Throwable e) {
            throw new ServiceUnavailableException("Tagging in source region is temporarily unavailable. Please retry later.");
        }
    }

    @Override
    public void copyTagsWithNewOwnerWithFallback(String fromCustomerId, Arn fromArn, String tagSetCustomerOwnerId, String
            fromTagSetId, Arn toArn, boolean excludeReservedTags, String newOwnerCustomerId) {
        copyTagsWithNewOwnerWithFallback(fromCustomerId, fromArn, tagSetCustomerOwnerId, fromTagSetId, toArn,
                excludeReservedTags, newOwnerCustomerId, null);
    }

    @Override
    public void copyTagsWithNewOwnerWithFallback(String fromCustomerId, Arn fromArn, String tagSetCustomerOwnerId, String
            fromTagSetId, Arn toArn, boolean excludeReservedTags, String newOwnerCustomerId, Long internalId) {
        try {
            taggingHelper.copyTagsWithNewOwnerWithFallback(fromCustomerId, fromArn, tagSetCustomerOwnerId, fromTagSetId, toArn,
                    excludeReservedTags, newOwnerCustomerId, internalId);
        } catch (RDSTaggingException e) {
            log().error(String.format("Error copying tags from customerId %s, from ARN %s [with fallback, tagSetOwnerId: %s, " +
                            "tagSetId: %s] to ARN %s [changing owner to %s], excludeReservedTags: %s",
                    fromCustomerId, fromArn.toString(), tagSetCustomerOwnerId, fromTagSetId, toArn.toString(), newOwnerCustomerId,
                    Boolean.toString(excludeReservedTags)), e);
        }
    }

    @Override
    public Map<String, String> listTagsForResource(String customerId, ListTagsForResourceRequest request) {
        return listTagsForResource(customerId, new Arn(request.getResourceName()));
    }

    @Override
    public Map<String, String> listTagsForResource(String customerId, Arn arn) {
        throwIfTaggingIsDisabled();

        validateResourceName(arn);

        verifyArn(customerId, arn);

        validateResourceExistenceAndRetrieveResource(arn);

        try {
            return getTagsForResource(customerId, arn);
        } catch (EntityNotFoundException entityNotFoundException) {
            return new HashMap<String, String>();
        }
    }

    @Override
    public void copyTagsToResourceRegionAware(String customerId, Arn fromArn, Arn toArn) {
        //toArn must refer a resource at current region
        verifyArn(customerId, toArn);

        if (fromArn.getRegion().equalsIgnoreCase(toArn.getRegion())) {
            //same region copy
            verifyArn(customerId, fromArn);
            Map<String, String> tags = getTagsForResource(customerId, fromArn);
            updateResource(customerId, toArn, tags, null, getInternalId(toArn));
        } else {
            //cross region copy
            Map<String, String> sourceTags = getTagSetForRemoteResource(fromArn);
            List<Tag> tagsToAdd = new ArrayList<Tag>();
            for(Map.Entry<String, String> en : sourceTags.entrySet()) {
                tagsToAdd.add(new Tag(en.getKey(), en.getValue()));
            }
            AddTagsToResourceRequest addTagsRequest = new AddTagsToResourceRequest();
            addTagsRequest.setResourceName(toArn.toString());
            addTagsRequest.setTagsToAdd(tagsToAdd);
            addTagsToResource(customerId, addTagsRequest);
        }
    }

    @Override
    public void clearTags(String customerId, Arn arn) {
        if (isTaggingEnabled()) {
            try {
                taggingHelper.clearTags(customerId, arn);
            } catch (RDSTaggingException e) {
                log().warn("Exception calling clearTags", e);
                throw new RuntimeException(e.getMessage(), e);
            }
        }
    }

    @Override
    public boolean isTaggingEnabled() {
        return taggingHelper.isTaggingEnabled();
    }

    @Override
    public boolean isClusterTagPropagationEnabled() {
        return serverConfigUtils.getConfigurationValueAsBooleanOrDefault(CLUSTER_TAG_PROPAGATION_ENABLED);
    }

    private void throwIfTaggingIsDisabled() {
        if(!isTaggingEnabled()) {
            throw new InvalidParameterCombinationException("Tagging is not currently supported in this region.");
        }
    }

    private Map<String, String> getTagSetForRemoteResource(final Arn resourceArn) {
        Exception e = null;

        try {
            return rdsInternalClientHelper.getResourceTags(resourceArn);
        } catch (Exception exception) {
            e = exception;
            log().warn("Exception calling getTagSetForRemoteRegion", e);
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    public List<RDSTaggingResourceTagMapping> getTagsForResourceList(String customerId, List<Arn> arnList) {
        try {
            return taggingHelper.getTagsForResourceList(customerId, arnList);
        } catch (RDSTaggingInvalidParameterException e) {
            // Wrap RDSTagging exceptions with Coral InvalidParameterValueException
            throw new InvalidParameterValueException(e.getMessage(), e);
        } catch (Exception e) {
            log().warn("Exception calling getTagsForResourceList", e);
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    public Map<String, String> getTagsForResource(String customerId, Arn arn) {
        try {
            return taggingHelper.getTagsForResource(customerId, arn);
        } catch (RDSTaggingInvalidParameterException e) {
            // Wrap RDSTagging exceptions with Coral InvalidParameterValueException
            throw new InvalidParameterValueException(e.getMessage(), e);
        } catch (Exception e) {
            log().warn("Exception calling getTagsForResourceList", e);
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    private void updateResource(String customerId, Arn arn, Map<String, String> addedTags, List<String> removedTags, Long internalId) {
        try {
            taggingHelper.updateResource(customerId, arn, addedTags, removedTags, internalId);
        } catch (RDSTaggingInvalidParameterException e) {
            throw new InvalidParameterValueException(e.getMessage(), e);
        } catch (RDSTaggingAccessDeniedException e) {
            throw new InvalidParameterCombinationException(e.getMessage(), e);
        } catch (RDSTaggingConcurrentAccessException e) {
            throw new InvalidParameterCombinationException(e.getMessage(), e);
        } catch (RDSTaggingInternalIdMismatchException e) {
            throw new InvalidParameterCombinationException(e.getMessage(), e);
        } catch (RDSTaggingTooManyTagsException e) {
            throw new InvalidParameterCombinationException(e.getMessage(), e);
        } catch (Exception e) {
            log().warn("Exception calling updateResource", e);
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    @Override
    public void deleteResource(String customerId, Arn arn) {
        try {
            taggingHelper.deleteResource(customerId, arn);
        } catch (RDSTaggingException e) {
            log().warn("Exception calling deleteResource", e);
        }
    }

    private Long getInternalId(Arn arn) {
        TaggableResource resource = validateResourceExistenceAndRetrieveResource(arn);
        return getInternalId(arn, resource);
    }

    private Long getInternalId(Arn arn, TaggableResource resource) {
        return resource.getInternalId();
    }

    private void validateResourceName(Arn arn) {
        try {
            validateResourceName(arn.toString());
        }
        catch (Exception e) {
            throw new InvalidParameterValueException("The parameter ResourceName"
                    + " must be provided and must not be blank.");
        }
    }

    private void validateResourceName(String resourceName) {
        if(StringUtils.isBlank(resourceName)) {
            throw new InvalidParameterValueException("The parameter ResourceName"
                    + " must be provided and must not be blank.");
        }
    }

    private void verifyArn(String customerId, Arn arn) {
        if (!ArnUtils.isValidArn(arn, regionCache.getRegion().getAwsRegionName(), customerId)) {
            throw new InvalidParameterValueException("The specified resource name does not match an RDS resource in this region.");
        }
    }

    private Map<String, String> validateTagsToAdd(List<Tag> tags, boolean calledFromCryo) {
        Map<String, String> validatedTags = Maps.newHashMap();

        for (Tag tag : tags) {
            validateTagKey(tag.getKey(), false, calledFromCryo);

            if(!StringUtils.isEmpty(tag.getValue())) {
                if(tag.getValue().length() > 256) {
                    throw new InvalidParameterValueException("Tag values must be between 0 and 256 characters in length.");
                }
                if(!Pattern.matches(VALID_TAG_CHARACTERS_REGEX, tag.getValue())) {
                    throw new InvalidParameterValueException("Tag values may only contain unicode letters, digits, whitespace, or one of these symbols: _ . : / = + - @");
                }
            }

            if (validatedTags.containsKey(tag.getKey())) {
                throw new InvalidParameterCombinationException("Duplicate tag key found in request: " + tag.getKey());
            }

            validatedTags.put(tag.getKey(), tag.getValue());
        }

        return validatedTags;
    }

    private void validateTagsToRemove(List<String> keys, boolean calledFromCryo) {
        for(String key : keys) {
            validateTagKey(key, true, calledFromCryo);
        }
    }

    private void validateTagKey(String key, boolean forRemove, boolean calledFromCryo) {
        if(StringUtils.isEmpty(key) || key.length() > 128) {
            throw new InvalidParameterValueException("Tag keys must be between 1 and 128 characters in length.");
        }

        // Cryo is allowed to manipulate aws:backup: tag keys
        if (calledFromCryo) {
            if (key.startsWith("aws:") && !key.startsWith(CryoHelper.CRYO_SYSTEM_TAG_KEY_PREFIX)) {
                throw new InvalidParameterValueException("AWS Backup is allowed only to manipulate tag keys " +
                        "starting with the reserved prefix \"" + CryoHelper.CRYO_SYSTEM_TAG_KEY_PREFIX + "\".");
            }
        }
        else {
            if (key.startsWith("aws:")) {
                if (forRemove) {
                    throw new InvalidParameterValueException("Tag keys starting with the reserved prefix \"aws:\" cannot be removed.");
                } else {
                    throw new InvalidParameterValueException("Tag keys cannot start with the reserved prefix \"aws:\".");
                }
            }
        }

        if(!Pattern.matches(VALID_TAG_CHARACTERS_REGEX, key)) {
            throw new InvalidParameterValueException("Tag keys may only contain unicode letters, digits, whitespace, or one of these symbols: _ . : / = + - @");
        }
    }

    private TaggableResource validateResourceExistenceAndRetrieveResource(Arn arn) {
        return ownershipValidator.validateResourceExistenceAndRetrieveResource(arn);
    }

    private EventLog log() {
        return EventLog.getThreadLocalEventLog();
    }
}