package io.mosip.authentication.internal.service.controller;

import io.mosip.authentication.core.constant.IdAuthCommonConstants;
import io.mosip.authentication.core.exception.IdAuthenticationBusinessException;
import io.mosip.authentication.core.logger.IdaLogger;
import io.mosip.authentication.core.spi.hotlist.service.HotlistService;
import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.core.websub.model.EventModel;
import io.mosip.kernel.websub.api.annotation.PreAuthenticateContentAndVerifyIntent;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import java.util.Map;

import static io.mosip.authentication.core.constant.IdAuthConfigKeyConstants.IDA_WEBSUB_HOTLIST_CALLBACK_SECRET;
import static io.mosip.authentication.core.constant.IdAuthConfigKeyConstants.IDA_WEBSUB_HOTLIST_TOPIC;

/**
 * @author Manoj SP
 * @author Mamta A
 */
@RestController
@Tag(name = "hotlist-event-controller", description = "Hotlist Event Controller")
public class HotlistEventController {

	private static Logger logger = IdaLogger.getLogger(HotlistEventController.class);

	@Autowired
	private HotlistService hotlistService;

	@PostMapping(value = "/callback/hotlist", consumes = "application/json")
	@Operation(summary = "handleHotlisting", description = "handleHotlisting", tags = { "hotlist-event-controller" })
	
	@ApiResponses(value = {
			@ApiResponse(responseCode = "200", description = "OK"),
			@ApiResponse(responseCode = "201", description = "Created" ,content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "401", description = "Unauthorized" ,content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "403", description = "Forbidden" ,content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "404", description = "Not Found" ,content = @Content(schema = @Schema(hidden = true)))})
	@PreAuthenticateContentAndVerifyIntent(secret = "${" + IDA_WEBSUB_HOTLIST_CALLBACK_SECRET
			+ "}", callback = "${ida-websub-hotlist-callback-relative-url}", topic = "${" + IDA_WEBSUB_HOTLIST_TOPIC
					+ "}")
	public void handleHotlisting(@RequestBody EventModel eventModel) throws IdAuthenticationBusinessException {
		logger.debug(IdAuthCommonConstants.SESSION_ID, "HotlistEventController", "handleHotlisting", "EVENT RECEIVED");
		try {
			Object eventType = eventModel != null && eventModel.getEvent() != null ? eventModel.getEvent().getType() : null;
			Map<String, Object> data = eventModel != null && eventModel.getEvent() != null ? eventModel.getEvent().getData() : null;
			Object id = data != null ? data.get("id") : null;
			Object idType = data != null ? data.get("idType") : null;
			Object status = data != null ? data.get("status") : null;
			Object expiryTimestamp = data != null ? data.get("expiryTimestamp") : null;
			logger.info(IdAuthCommonConstants.SESSION_ID, "HotlistEventController", "handleHotlisting",
					"WebSub hotlist callback - eventType=" + String.valueOf(eventType) + ", idType=" + idType + ", status=" + status
							+ ", id=" + id + ", expiryTimestamp=" + expiryTimestamp);
		} catch (Exception e) {
			logger.warn(IdAuthCommonConstants.SESSION_ID, "HotlistEventController", "handleHotlisting",
					"Failed to log hotlist callback payload details.");
		}
		hotlistService.handlingHotlistingEvent(eventModel);
	}

}
