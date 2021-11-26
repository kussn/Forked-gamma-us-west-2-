package com.amazonaws.concierge.workflows.batch.inference.metering;

import amazon.platform.config.AppConfig;
import amazon.rds.flux.step.Attribute;
import amazon.rds.flux.step.StepApply;
import amazon.rds.flux.step.StepResult;
import amazon.rds.flux.step.WorkflowStep;
import com.amazon.coral.metrics.Metrics;
import com.amazonaws.concierge.metrics.BasicMetrics;
import com.amazonaws.concierge.resource.BatchInferenceJob;
import com.amazonaws.concierge.resource.dao.BatchInferenceJobDAO;
import static com.amazonaws.concierge.workflows.batch.inference.BatchInferenceUtil.getPostProcessLocation;
import static com.amazonaws.concierge.workflows.batch.inference.BatchInferenceUtil.getDirectoryPrefix;
import com.amazonaws.concierge.util.Arn;
import com.amazonaws.concierge.util.Metering.MeteringConstants;
import com.amazonaws.concierge.util.Metering.Operation;
import com.amazonaws.concierge.util.Metering.UsageType;
import com.amazonaws.concierge.workflows.solution.steps.MeterTrainingStep;
import com.amazonaws.concierge.workflows.utils.CommonAttributes;
import com.amazonaws.concierge.workflows.utils.RetryUtil;
import com.amazonaws.concierge.workflows.utils.S3Util;
import com.amazonaws.services.cloudtrail.model.S3BucketDoesNotExistException;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.sqs.AmazonSQS;
import com.amazonaws.services.sqs.model.GetQueueUrlRequest;
import com.amazonaws.services.sqs.model.SendMessageRequest;
import com.google.common.base.Throwables;
import com.google.common.collect.Maps;
import com.google.gson.Gson;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;

import java.io.InputStream;
import java.net.URISyntaxException;
import java.util.Map;

/**
 * Meter batch inference job
 */
@Slf4j
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class MeterBatchInference implements WorkflowStep {
    private static final String METRIC_CLASS = MeterTrainingStep.class.getSimpleName();
    private static final String BATCH_RESULT_SUCCESS_COUNT_KEY = "successCount";
    private static final String METERING_QUEUE_NAME = AppConfig.findString("Metering.SQSQueueName");
    private static final String RESULT_S3_OBJECT= "/metrics/metrics.json";
    private static final Gson gson = new Gson();

    private final AmazonSQS amazonSQS;
    private final AmazonS3 s3;
    private final BatchInferenceJobDAO<BatchInferenceJob> batchInferenceJobDAO;

    @StepApply
    public StepResult apply(Metrics metrics,
                            @Attribute(CommonAttributes.ACCOUNT_ID) String accountId,
                            @Attribute(CommonAttributes.WF_MAIN_RESOURCE_ARN) String batchInferenceJobArnStr,
                            @Attribute(CommonAttributes.RESOURCE_ARN_MAP) Map<String, String> resourceArnMap) {

        Arn batchInferenceJobArn = Arn.fromString(batchInferenceJobArnStr);

        try (BasicMetrics basicMetrics = new BasicMetrics(METRIC_CLASS, metrics, false)) {
            BatchInferenceJob batchInferenceJob = batchInferenceJobDAO.get(accountId, batchInferenceJobArn);
            String s3DirectoryPrefix = getDirectoryPrefix(batchInferenceJob);
            String resultLocation = getPostProcessLocation(s3DirectoryPrefix) + RESULT_S3_OBJECT;
            InputStream objectData;
            int recommendationsCount = 0;
            try {
                S3Util s3Util = new S3Util(s3);
                objectData = s3Util.getS3ObjectContents(resultLocation);
                Map<String, Integer> resultFromS3Object = s3Util.parseS3MetricJSONContents(objectData);
                if (!resultFromS3Object.isEmpty()) {
                    recommendationsCount = resultFromS3Object.getOrDefault(BATCH_RESULT_SUCCESS_COUNT_KEY, 0);
                }
            } catch (URISyntaxException e) {
                String err = String.format("Invalid S3 URI to get batch inferences: %s", resultLocation);
                log.error(err);
                return StepResult.failure(err);
            } catch (S3BucketDoesNotExistException e) {
                String err = String.format("Invalid S3 Bucket for batch inferences at %s", resultLocation);
                log.error(err);
                return StepResult.failure(err);
            } catch (Exception e) {
                log.error("Failed to parse JSON content for batch metering {}", batchInferenceJobArn, e);
                return StepResult.failure(String.format("Failed to parse JSON content for batch metering %s", batchInferenceJobArn));
            }

            Map<String, String> meteringMap = Maps.newHashMapWithExpectedSize(4);
            meteringMap.put(MeteringConstants.ARN_KEY, batchInferenceJobArnStr);
            meteringMap.put(MeteringConstants.OPERATION_NAME, Operation.INFERENCE_BATCH.toString());
            meteringMap.put(MeteringConstants.USAGE_TYPE, UsageType.BATCH_INFERENCE.toString());
            meteringMap.put(MeteringConstants.USAGE_VALUE, String.valueOf(recommendationsCount));

            String queueUrl = amazonSQS.getQueueUrl(new GetQueueUrlRequest().withQueueName(METERING_QUEUE_NAME)).getQueueUrl();
            SendMessageRequest request = new SendMessageRequest()
                    .withQueueUrl(queueUrl)
                    .withMessageBody(gson.toJson(meteringMap));

            amazonSQS.sendMessage(request);
            log.info("BatchInferenceCount: {}", recommendationsCount);
            basicMetrics.recordSuccessAndClose();
        } catch (Exception e) {
            String errorWithStackTrace = String.format("Error while generating metering record: %s", Throwables.getStackTraceAsString(e));
            log.error(errorWithStackTrace);

            if (RetryUtil.isRetryable(e)) {
                return StepResult.retry(errorWithStackTrace);
            }

            return StepResult.failure(errorWithStackTrace);
        }

        return StepResult.success();
    }
}