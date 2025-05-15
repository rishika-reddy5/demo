package com.availabilitySchedule.dto;

import com.availabilitySchedule.model.Availability;
import com.availabilitySchedule.model.Specialization;
import com.availabilitySchedule.model.Status;
import com.availabilitySchedule.model.Timeslots;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;

/**
 * Data Transfer Object for Availability. Converts between Availability entity
 * and DTO.
 * 
 * @author Swapnil Rajesh
 * @since 18/02/2025
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class AvailabilityDTO {
	private Long availabilityId;
	private Long doctorId;
	private String doctorName;
	private Specialization specialization;
	private LocalDate date;
	private Timeslots timeSlots;

	public Availability toEntity() {
		Availability availability = new Availability();
		availability.setAvailabilityId(availabilityId);
		availability.setDoctorId(this.doctorId);
		availability.setDoctorName(this.doctorName);
		availability.setSpecialization(this.specialization);
		availability.setDate(this.date);
		availability.setTimeSlots(this.timeSlots);
		availability.setStatus(Status.Available);

		return availability;
	}

	public static AvailabilityDTO fromEntity(Availability availability) {
		AvailabilityDTO dto = new AvailabilityDTO();
		dto.setAvailabilityId(availability.getAvailabilityId());
		dto.setDoctorId(availability.getDoctorId());
		dto.setDoctorName(availability.getDoctorName());
		dto.setSpecialization(availability.getSpecialization());
		dto.setDate(availability.getDate());
		dto.setTimeSlots(availability.getTimeSlots());
		return dto;
	}
}