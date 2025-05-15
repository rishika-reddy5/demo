package com.availabilitySchedule.service;

import com.availabilitySchedule.dto.AvailabilityDTO;
import com.availabilitySchedule.exception.AvailabilityNotFoundException;
import com.availabilitySchedule.exception.DoctorNotFoundException;
import com.availabilitySchedule.exception.UnavailableException;
import com.availabilitySchedule.model.Availability;
import com.availabilitySchedule.model.Specialization;
import com.availabilitySchedule.model.Status;
import com.availabilitySchedule.model.Timeslots;
import com.availabilitySchedule.repository.AvailabilityRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.DayOfWeek;
import java.time.LocalDate;
import java.time.temporal.TemporalAdjusters;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Slf4j
@Service
public class AvailabilityService {

    @Autowired
    private AvailabilityRepository availabilityRepository;
    
    
    public void createAvailabilityForDoctorId(Long doctorId, String doctorName, Specialization specialization, List<AvailabilityDTO> availabilityList) {
        log.info("Manually creating availability for Doctor ID: {}", doctorId);

        for (AvailabilityDTO dto : availabilityList) {
            boolean exists = availabilityRepository.existsByDoctorIdAndDateAndTimeSlots(doctorId, dto.getDate(), dto.getTimeSlots());

            if (!exists) { // Prevent duplicate entries
                Availability availability = new Availability();
                availability.setDoctorId(doctorId);
                availability.setDoctorName(doctorName);
                availability.setSpecialization(specialization);
                availability.setDate(dto.getDate());
                availability.setTimeSlots(dto.getTimeSlots());
                availability.setStatus(Status.Available);

                availabilityRepository.save(availability);
            }
        }

        log.info("Availability manually set for Doctor ID: {}", doctorId);
    }

//    public void createAvailabilityForDoctorId(Long doctorId, String doctorName, Specialization specialization) {
//        log.info("Generating availability for Doctor ID: {}", doctorId);
//
//        LocalDate startDate = LocalDate.now().with(TemporalAdjusters.previousOrSame(DayOfWeek.MONDAY));
//        LocalDate nextWeekStart = startDate.plusWeeks(1);
//
//        for (int i = 0; i < 5; i++) { // Monday to Friday
//            LocalDate date = startDate.plusDays(i);
//
//            for (Timeslots timeSlot : Timeslots.values()) {
//                boolean exists = availabilityRepository.existsByDoctorIdAndDateAndTimeSlots(doctorId.toString(), date, timeSlot);
//
//                if (!exists) { // Prevent duplicate entries
//                    Availability availability = new Availability();
//                    availability.setDoctorId(doctorId.toString());
//                    availability.setDoctorName(doctorName);
//                    availability.setSpecialization(specialization);
//                    availability.setDate(date);
//                    availability.setTimeSlots(timeSlot);
//                    availability.setStatus(Status.Available);
//
//                    availabilityRepository.save(availability);
//                }
//            }
//        }
//
//        log.info("Availability created for Doctor ID: {} for this week.", doctorId);
//
//        for (int i = 0; i < 5; i++) { // Next week's availability
//            LocalDate date = nextWeekStart.plusDays(i);
//
//            for (Timeslots timeSlot : Timeslots.values()) {
//                boolean exists = availabilityRepository.existsByDoctorIdAndDateAndTimeSlots(doctorId.toString(), date, timeSlot);
//
//                if (!exists) {
//                    Availability availability = new Availability();
//                    availability.setDoctorId(doctorId.toString());
//                    availability.setDoctorName(doctorName);
//                    availability.setSpecialization(specialization);
//                    availability.setDate(date);
//                    availability.setTimeSlots(timeSlot);
//                    availability.setStatus(Status.Available);
//
//                    availabilityRepository.save(availability);
//                }
//            }
//        }
//
//        log.info("Availability created for Doctor ID: {} for next week.", doctorId);
//    }

//
//    // ✅ Doctors manually set availability
//    public void saveDoctorAvailability(String doctorId, String doctorName, Specialization specialization, List<AvailabilityDTO> availabilityList) {
//        for (AvailabilityDTO dto : availabilityList) {
//            boolean exists = availabilityRepository.existsByDoctorIdAndDateAndTimeSlots(
//                dto.getDoctorId(), dto.getDate(), dto.getTimeSlots()
//            );
//
//            if (!exists) {
//                Availability availability = dto.toEntity();
//                availability.setDoctorId(doctorId);
//                availability.setDoctorName(doctorName);
//                availability.setSpecialization(specialization);
//                availabilityRepository.save(availability);
//            }
//        }
//    }

    
    
    public AvailabilityDTO getAvailabilityById(Long availabilityId) {
        Optional<Availability> availability = availabilityRepository.findById(availabilityId);

        if (!availability.isPresent()) {
            throw new AvailabilityNotFoundException("Availability ID not found: " + availabilityId);
        }

        return AvailabilityDTO.fromEntity(availability.get());
    }

    public List<Availability> getAvailabilityByDoctorIdAndDate(Long doctorId, LocalDate date) {
        List<Availability> availabilityList = availabilityRepository.findByDoctorIdAndDate(doctorId, date);

        if (availabilityList.isEmpty()) {
            throw new UnavailableException("No availability slots found for Doctor ID: " + doctorId + " on " + date);
        }

        return availabilityList.stream()
                .filter(availability -> availability.getStatus() == Status.Available)
                .collect(Collectors.toList());
    }
 
    // ✅ Fetch a doctor's availability for patients
    public List<Availability> getDoctorAvailability(Long doctorId) {
        List<Availability> availabilitySlots = availabilityRepository.findByDoctorId(doctorId);

        if (availabilitySlots.isEmpty()) {
            throw new DoctorNotFoundException("No availability slots found for Doctor ID: " + doctorId);
        }

        return availabilitySlots;
    }

    // ✅ Fetch availability by specialization & date
    public List<Availability> getAvailabilityBySpecializationAndDate(Specialization specialization, LocalDate date) {
        List<Availability> availabilities = availabilityRepository.findBySpecializationAndDate(specialization, date);

        if (availabilities.isEmpty()) {
            throw new UnavailableException("No available slots for specialization: " + specialization);
        }

        return availabilities.stream()
                .filter(availability -> availability.getStatus() == Status.Available)
                .collect(Collectors.toList());
    }

    // ✅ Book a specific time slot
    public void bookTimeSlot(Long availabilityId) {
        Availability availability = availabilityRepository.findById(availabilityId)
                .orElseThrow(() -> new AvailabilityNotFoundException("Availability not found for ID: " + availabilityId));

        if (availability.getStatus() != Status.Available) {
            throw new UnavailableException("Time slot is not available for booking");
        }

        availability.setStatus(Status.Booked);
        availabilityRepository.save(availability);
    }

    // ✅ Cancel a booked appointment slot
    public void cancelAvailabilityStatus(Long availabilityId) {
        Availability availability = availabilityRepository.findById(availabilityId)
                .orElseThrow(() -> new AvailabilityNotFoundException("Availability not found for ID: " + availabilityId));

        if (availability.getStatus() == Status.Booked) {
            availability.setStatus(Status.Available);
            availabilityRepository.save(availability);
        } else {
            throw new UnavailableException("Time slot is not booked for cancellation");
        }
    }

    // ✅ View all available doctor slots
    public List<Availability> viewAllAvailabilities() {
        return availabilityRepository.findAll()
                .stream()
                .filter(availability -> availability.getStatus() == Status.Available)
                .collect(Collectors.toList());
    }

    // ✅ Delete an availability slot
    public void deleteAvailability(Long availabilityId) {
        availabilityRepository.deleteById(availabilityId);
    }
}
